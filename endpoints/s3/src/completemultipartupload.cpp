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
#include <spdlog/spdlog.h>
#include <regex>
#include <cstdio>
#include <vector>
#include <mutex>
#include <memory>
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

void irods::s3::actions::handle_completemultipartupload(
	irods::http::session_pointer_type session_ptr,
	boost::beast::http::request_parser<boost::beast::http::empty_body>& empty_body_parser,
	const boost::urls::url_view& url)
{
	namespace part_shmem = irods::s3::api::multipart_global_state;

	beast::http::response<beast::http::empty_body> response;

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

	std::filesystem::path s3_bucket;
	std::filesystem::path s3_key;

	bool on_bucket = true;
	for (auto seg : url.encoded_segments()) {
		if (on_bucket) {
			on_bucket = false;
			s3_bucket = seg.decode();
		}
		else {
			s3_key = s3_key / seg.decode();
		}
	}

	logging::debug("{} s3_bucket={} s3_key={}", __func__, s3_bucket.string(), s3_key.string());

	fs::path path;
	if (auto bucket = irods::s3::resolve_bucket(url.segments()); bucket.has_value()) {
		path = bucket.value();
		path = irods::s3::finish_path(path, url.segments());
		logging::debug("{}: CompleteMultipartUpload path={}", __func__, path.string());
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

	beast::http::response<beast::http::string_body> string_body_response(std::move(response));
	string_body_response.result(beast::http::status::ok);

	// change the parser to a string_body parser and read the body
	empty_body_parser.eager(true);
	beast::http::request_parser<boost::beast::http::string_body> parser{std::move(empty_body_parser)};
	beast::http::read(session_ptr->stream().socket(), session_ptr->get_buffer(), parser);

	std::string& request_body = parser.get().body();
	logging::debug("{}: request_body\n{}", __func__, request_body);

	int max_part_number = -1;
	int min_part_number = 1000;
	int part_number_count = 0;
	boost::property_tree::ptree request_body_property_tree;
	try {
		std::stringstream ss;
		ss << request_body;
		boost::property_tree::read_xml(ss, request_body_property_tree);
		for (boost::property_tree::ptree::value_type& v :
		     request_body_property_tree.get_child("CompleteMultipartUpload")) {
			const std::string& tag = v.first;
			if (tag == "Part") {
				for (boost::property_tree::ptree::value_type& v2 : v.second) {
					const std::string& tag = v2.first;
					if (tag == "PartNumber") {
						int current_part_number = v2.second.get_value<int>();
						if (current_part_number < min_part_number) {
							min_part_number = current_part_number;
						}
						if (current_part_number > max_part_number) {
							max_part_number = current_part_number;
						}
						++part_number_count;
					}
				}
			}
		}
	}
	catch (boost::property_tree::xml_parser_error& e) {
		logging::debug("{}: Could not parse XML body.", __func__);
		response.result(boost::beast::http::status::bad_request);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}
	catch (...) {
		logging::debug("{}: Unknown error parsing XML body.", __func__);
		response.result(boost::beast::http::status::bad_request);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	// At this point we are just checking that the part numbers start
	// with 1 and the largest part number is the same as the count of
	// part numbers.  We could later check that each part number is included...
	if (min_part_number != 1) {
		logging::debug("{}: Part numbers did not start with 1.", __func__);
		response.result(boost::beast::http::status::bad_request);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	if (max_part_number != part_number_count) {
		logging::debug("{}: Missing at least one part number.", __func__);
		response.result(boost::beast::http::status::bad_request);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	// debug
	if (spdlog::get_level() == spdlog::level::debug || spdlog::get_level() == spdlog::level::trace) {
		std::lock_guard<std::mutex> guard(part_shmem::multipart_global_state_mutex);
		logging::info("{}:{} {}: ******* THIS RAN ********", __FILE__, __LINE__, __func__);

		if (part_shmem::part_size_map.find(upload_id) != part_shmem::part_size_map.end()) {
			logging::debug("{}:{} {}: ------------------", __FILE__, __LINE__, __func__);
			for (int i = 1; i <= part_number_count; ++i) {
				bool found = part_shmem::part_size_map[upload_id].find(i) != part_shmem::part_size_map[upload_id].end();
				if (found) {
					logging::debug(
						"{}:{} {}: {}: {}", __FILE__, __LINE__, __func__, i, part_shmem::part_size_map[upload_id][i]);
				}
				else {
					logging::debug("{}:{} {}: {}: UNKNOWN", __FILE__, __LINE__, __func__, i);
				}
			}
			logging::debug("{}:{} {}: ------------------", __FILE__, __LINE__, __func__);
		}
	}

	// build up a vector filenames, offsets, and lengths for each part
	std::vector<part_info> part_info_vector;
	part_info_vector.reserve(max_part_number);

	// get the base location for the part files
	const nlohmann::json& config = irods::http::globals::configuration();
	std::string part_file_location =
		config.value(nlohmann::json::json_pointer{"/s3_server/multipart_upload_part_files_directory"}, ".");

	{
		std::lock_guard<std::mutex> guard(part_shmem::multipart_global_state_mutex);
		uint64_t offset_counter = 0;
		for (int current_part_number = 1; current_part_number <= max_part_number; ++current_part_number) {
			std::string part_filename =
				part_file_location + "/irods_s3_api_" + upload_id + "." + std::to_string(current_part_number);

			if (part_shmem::part_size_map.find(upload_id) != part_shmem::part_size_map.end() &&
			    part_shmem::part_size_map[upload_id].find(current_part_number) !=
			        part_shmem::part_size_map[upload_id].end())
			{
				// get size from part_size_map in shmem
				auto part_size = part_shmem::part_size_map[upload_id][current_part_number];
				part_info_vector.push_back({part_filename, offset_counter, part_size});
				offset_counter += part_size;
			}
			else {
				// get size from part files
				try {
					auto part_size = std::filesystem::file_size(part_filename);
					part_info_vector.push_back({part_filename, offset_counter, part_size});
					offset_counter += part_size;
				}
				catch (fs::filesystem_error& e) {
					logging::error("{}: Failed locate part", __func__);
					response.result(beast::http::status::internal_server_error);
					logging::debug("{}: returned [{}]", __func__, response.reason());
					session_ptr->send(std::move(response));
					return;
				}
			}
		}
	}

	uint64_t read_buffer_size = irods::s3::get_put_object_buffer_size_in_bytes();

	upload_status upload_status_object;
	std::condition_variable cv;
	std::mutex cv_mutex;

	// get the replica_token and replica_number from replica_token_number_and_odstream_map
	const auto& replica_token = std::get<0>(part_shmem::replica_token_number_and_odstream_map[upload_id]);
	const auto& replica_number = std::get<1>(part_shmem::replica_token_number_and_odstream_map[upload_id]);

	// start tasks on thread pool for part uploads
	for (int current_part_number = 1; current_part_number <= max_part_number; ++current_part_number) {
		logging::debug(
			"{}: pushing upload work on thread pool {}-{} : [filename={}][offset={}][size={}]",
			__func__,
			upload_id,
			current_part_number,
			part_info_vector[current_part_number - 1].part_filename,
			part_info_vector[current_part_number - 1].part_offset,
			part_info_vector[current_part_number - 1].part_size);

		irods::http::globals::background_task(
			[session_ptr,
		     irods_username,
		     path,
		     &cv_mutex,
		     &cv,
		     &upload_status_object,
		     &replica_token,
		     &replica_number,
		     current_part_number,
		     upload_id,
		     part_filename = part_info_vector[current_part_number - 1].part_filename,
		     part_offset = part_info_vector[current_part_number - 1].part_offset,
		     part_size = part_info_vector[current_part_number - 1].part_size, // don't really need this
		     read_buffer_size,
		     func = __func__]() mutable {
				uint64_t read_write_byte_counter = 0;

				// upon exit, increment the task_done_counter and notify the coordinating thread
				const irods::at_scope_exit signal_done{[&cv_mutex,
			                                            &cv,
			                                            &upload_status_object,
			                                            upload_id,
			                                            current_part_number,
			                                            part_offset,
			                                            part_size,
			                                            &read_write_byte_counter,
			                                            func]() {
					{
						std::lock_guard<std::mutex> lk(cv_mutex);
						(upload_status_object.task_done_counter)++;
					}
					logging::debug(
						"{}: upload_id={} part_number={} wrote {} bytes at offset {} - part_size={}",
						func,
						upload_id,
						current_part_number,
						read_write_byte_counter,
						part_offset,
						part_size);
					cv.notify_one();
				}};

				// create a read/write buffer
				std::vector<char> buf_vector(read_buffer_size);

				// open the part file
				std::ifstream ifs;
				ifs.open(part_filename, std::ifstream::in);

				if (!ifs.is_open()) {
					// if there is no part file then this part was uploaded directly to iRODS
					logging::debug(
						"{}: upload_id={} part_number={} Part was uploaded directly to iRODS. Skipping...",
						func,
						upload_id,
						current_part_number);
					return;
				}

				// open dstream for writing to iRODS
				auto conn = irods::get_connection(*irods_username);
				irods::experimental::io::client::default_transport xtrans{conn};
				irods::experimental::io::dstream ds; // irods dstream for writing directly to irods
				ds.open(
					xtrans,
					replica_token,
					path,
					irods::experimental::io::replica_number{replica_number}); //, std::ios::out | std::ios::ate);

				if (!ds.is_open()) {
					std::lock_guard<std::mutex> lk(cv_mutex);
					upload_status_object.fail_flag = true;
					std::stringstream ss;
					ss << "Failed to open dstream to iRODS path=" << path;
					upload_status_object.error_string = ss.str();
					logging::error(
						"{}: {} upload_id={} part_number={}",
						func,
						upload_status_object.error_string,
						upload_id,
						current_part_number);
					return;
				}

				// seek to start of part
				ds.seekp(part_offset);

				// read the file in parts into buffer and stream to iRODS
				while (ifs) {
					// if someone failed then bail
					{
						std::lock_guard<std::mutex> lk(cv_mutex);
						if (upload_status_object.fail_flag) {
							break;
						}
					}

					// Try to read next chunk of data
					ifs.read(buf_vector.data(), read_buffer_size);
					size_t read_bytes = ifs.gcount();
					read_write_byte_counter += read_bytes;
					if (read_bytes) {
						ds.write((char*) buf_vector.data(), read_bytes);

						if (ds.fail()) {
							std::lock_guard<std::mutex> lk(cv_mutex);
							upload_status_object.fail_flag = true;
							upload_status_object.error_string = "Failed in writing part to iRODS";
							logging::error(
								"{}: {} upload_id={} part_number={}",
								func,
								upload_status_object.error_string,
								upload_id,
								current_part_number);
							break;
						}
					}
				}

				ds.close();
				ifs.close();
				return;
			});
	}

	// wait until all threads are complete
	std::unique_lock<std::mutex> lk(cv_mutex);
	cv.wait(lk, [&upload_status_object, max_part_number, func = __func__]() {
		logging::debug("{}: wait: task_done_counter is {}", func, upload_status_object.task_done_counter);
		return upload_status_object.task_done_counter == max_part_number;
	});

	// close the object and delete the entry in the replica_token_number_and_odstream_map
	if (part_shmem::replica_token_number_and_odstream_map.find(upload_id) !=
	    part_shmem::replica_token_number_and_odstream_map.end())
	{
		// Read all of the shared pointers in the tuple to make sure they are destructed in
		// the order we require. std::tuple does not guarantee order of destruction.
		auto conn_ptr = std::get<2>(part_shmem::replica_token_number_and_odstream_map[upload_id]);
		auto transport_ptr = std::get<3>(part_shmem::replica_token_number_and_odstream_map[upload_id]);
		auto dstream_ptr = std::get<4>(part_shmem::replica_token_number_and_odstream_map[upload_id]);

		logging::trace("{}:{} Closing iRODS data object.", __func__, __LINE__);
		if (dstream_ptr) {
			dstream_ptr->close();
		}

		// delete the entry
		part_shmem::replica_token_number_and_odstream_map.erase(upload_id);
	}

	// check to see if any threads failed
	if (upload_status_object.fail_flag) {
		logging::error("{}: {}", __func__, upload_status_object.error_string);
		response.result(beast::http::status::internal_server_error);
		logging::debug("{}: returned [{}]", __func__, response.reason());
		session_ptr->send(std::move(response));
		return;
	}

	// remove the temporary part files - on failures we don't want to clean up as this could be resent
	for (int i = 0; i < max_part_number; ++i) {
		std::remove(part_info_vector[i].part_filename.c_str());
	}

	// clean up shmem - on failures we don't want to clean up as this could be resent
	{
		std::lock_guard<std::mutex> guard(part_shmem::multipart_global_state_mutex);
		part_shmem::part_size_map.erase(upload_id);
	}

	// Now send the response
	// Example response:
	// <CompleteMultipartUploadResult>
	//     <Location>string</Location>
	//     <Bucket>string</Bucket>
	//     <Key>string</Key>
	//     <ETag>string</ETag>
	//  </CompleteMultipartUploadResult>

	boost::property_tree::ptree document;
	boost::property_tree::xml_parser::xml_writer_settings<std::string> settings;
	settings.indent_char = ' ';
	settings.indent_count = 4;
	std::stringstream s;

	std::string s3_region = irods::s3::get_s3_region();

	document.add("CompleteMultipartUploadResult.Location", s3_region);
	document.add("CompleteMultipartUploadResult.Bucket", s3_bucket.string());
	document.add("CompleteMultipartUploadResult.Key", s3_key);
	document.add("CompleteMultipartUploadResult.ETag", "TBD");

	boost::property_tree::write_xml(s, document, settings);
	string_body_response.body() = s.str();
	logging::debug("{}: response\n{}", __func__, s.str());
	string_body_response.result(boost::beast::http::status::ok);
	logging::debug("{}: returned [{}]", __func__, string_body_response.reason());
	session_ptr->send(std::move(string_body_response));
	return;
}
