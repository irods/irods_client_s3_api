#include "irods/private/s3_api/s3_api.hpp"
#include "irods/private/s3_api/authentication.hpp"
#include "irods/private/s3_api/bucket.hpp"
#include "irods/private/s3_api/common_routines.hpp"
#include "irods/private/s3_api/connection.hpp"
#include "irods/private/s3_api/log.hpp"
#include "irods/private/s3_api/common.hpp"
#include "irods/private/s3_api/session.hpp"
#include "irods/private/s3_api/configuration.hpp"
#include "irods/private/s3_api/globals.hpp"

#include <irods/dstream.hpp>
#include <irods/transport/default_transport.hpp>
#include <irods/irods_exception.hpp>
#include <irods/irods_at_scope_exit.hpp>

#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include <fmt/format.h>
#include <regex>
#include <cstdio>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <thread>
#include <chrono>
#include <string>
#include <sstream>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace fs = irods::experimental::filesystem;
namespace logging = irods::http::logging;

namespace irods::s3::api::multipart_global_state
{
	extern std::unordered_map<std::string, std::unordered_map<unsigned int, uint64_t>> part_size_map;
	extern std::unordered_map<
		std::string,
		std::tuple<
			irods::experimental::io::replica_token,
			irods::experimental::io::replica_number,
			std::shared_ptr<irods::experimental::client_connection>,
			std::shared_ptr<irods::experimental::io::client::native_transport>,
			std::shared_ptr<irods::experimental::io::odstream>>>
		replica_token_number_and_odstream_map;

	extern std::mutex multipart_global_state_mutex;
} // end namespace irods::s3::api::multipart_global_state

namespace
{

	std::regex upload_id_pattern("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");

	// store offsets and lengths for each part
	struct part_info
	{
		std::string part_filename;
		uint64_t part_offset;
		uint64_t part_size;
	};

	struct upload_status
	{
		int task_done_counter = 0;
		bool fail_flag = false;
		std::string error_string;
	};
} //namespace

void irods::s3::actions::handle_abortmultipartupload(
	irods::http::session_pointer_type session_ptr,
	boost::beast::http::request_parser<boost::beast::http::empty_body>& empty_body_parser,
	const boost::urls::url_view& url)
{
	namespace part_shmem = irods::s3::api::multipart_global_state;

	beast::http::response<beast::http::empty_body> response;
	response.result(beast::http::status::ok);

	// Authenticate
	auto irods_username = irods::s3::authentication::authenticates(empty_body_parser, url);
	if (!irods_username) {
		logging::error("{}: Failed to authenticate.", __func__);
		response.result(beast::http::status::forbidden);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	auto conn = irods::get_connection(*irods_username);

	fs::path path;
	if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
		path = bucket.value();
		path = irods::s3::finish_path(path, url.segments());
		logging::debug("{}: AbortMultipartUpload path={}", __func__, path.string());
	}
	else {
		logging::error("{}: Failed to resolve bucket", __func__);
		response.result(beast::http::status::forbidden);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	// get the uploadId from the param list
	std::string upload_id;
	if (const auto upload_id_param = url.params().find("uploadId"); upload_id_param != url.params().end()) {
		upload_id = (*upload_id_param).value;
	}

	if (upload_id.empty()) {
		logging::error("{}: Did not receive an uploadId", __func__);
		response.result(beast::http::status::bad_request);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	// Do not allow an upload_id that is not in the format we have defined. People could do bad things
	// if we didn't enforce this.
	if (!std::regex_match(upload_id, upload_id_pattern)) {
		logging::error("{}: Upload ID [{}] was not in expected format.", __func__, upload_id);
		response.result(beast::http::status::bad_request);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	// delete the entry in the replica_token_number_and_odstream_map
	if (part_shmem::replica_token_number_and_odstream_map.find(upload_id) !=
	    part_shmem::replica_token_number_and_odstream_map.end())
	{
		// Read all of the shared pointers in the tuple to make sure they are destructed in
		// the order we require. std::tuple does not guarantee order of destruction.
		auto conn_ptr = std::get<2>(part_shmem::replica_token_number_and_odstream_map[upload_id]);
		auto transport_ptr = std::get<3>(part_shmem::replica_token_number_and_odstream_map[upload_id]);
		auto dstream_ptr = std::get<4>(part_shmem::replica_token_number_and_odstream_map[upload_id]);
		if (dstream_ptr) {
			dstream_ptr->close();
		}

		// delete the entry
		part_shmem::replica_token_number_and_odstream_map.erase(upload_id);
	}

	// get the base location for the part files
	const nlohmann::json& config = irods::http::globals::configuration();
	std::string part_file_location =
		config.value(nlohmann::json::json_pointer{"/s3_server/multipart_upload_part_files_directory"}, ".");

	// remove the temporary part files - <part_file_location>/irods_s3_api_<upload_id>.[N]
	std::string part_file_regex_str = "irods_s3_api_" + upload_id + "\\.[0-9]+";
	std::regex part_files_regex(part_file_regex_str);
	const std::filesystem::directory_iterator end;
	try {
		for (std::filesystem::directory_iterator iter{part_file_location}; iter != end; ++iter) {
			if (std::filesystem::is_regular_file(*iter)) {
				if (std::regex_match(iter->path().filename().string(), part_files_regex)) {
					try {
						std::filesystem::remove(iter->path());
					}
					catch (std::exception&) {
						logging::error(
							"{}: Failed to remove part_file [{}].", __func__, iter->path().filename().string());
						response.result(beast::http::status::internal_server_error);
					}
				}
			}
		}
	}
	catch (std::exception& e) {
		logging::error(
			"{}: Upload ID [{}] - Exception caught when iterating through part files for removal - {}.",
			__func__,
			upload_id,
            e.what());
		response.result(beast::http::status::internal_server_error);
	}

	// clean up shmem - on failures we don't want to clean up as this could be resent
	{
		std::lock_guard<std::mutex> guard(part_shmem::multipart_global_state_mutex);
		part_shmem::part_size_map.erase(upload_id);
	}

	logging::debug("{}: returned [{}]", __func__, response.reason());
	session_ptr->send(std::move(response));
	return;
} // handle_abortmultipartupload
