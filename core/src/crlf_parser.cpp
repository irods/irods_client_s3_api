#include "irods/private/s3_api/crlf_parser.hpp"

#include "irods/private/s3_api/log.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/beast/http/rfc7230.hpp>

#include <fmt/format.h>

namespace irods::http
{
	auto get_multipart_form_data_boundary(const std::string_view _data) -> std::optional<std::string_view>
	{
		// The ext_list type does not treat "multipart/form-data" as a single string.
		// I'm not sure if this is by design, but we have to skip the multipart/ prefix so that
		// ext_list can extract the boundary argument.
		//
		// TODO Consider opening an issue for Boost.Beast in Github.

		const auto pos = _data.find("form-data");

		if (pos == std::string_view::npos) {
			return std::nullopt;
		}

		boost::beast::http::ext_list list{_data.substr(pos)};
		const auto iter = list.find("form-data");

		if (iter == std::end(list)) {
			logging::error("{}: Missing [boundary] parameter in [multipart/form-data] value.", __func__);
			return std::nullopt;
		}

		for (auto&& param : iter->second) {
			if (param.first == "boundary") {
				logging::debug("PARAM = (name={}, value={})", param.first, param.second);
				return param.second;
			}
		}

		return std::nullopt;
	} // get_multipart_form_data_boundary

	auto parse_multipart_form_data(const std::string_view _boundary, const std::string_view _data)
		-> query_arguments_type
	{
		if (_data.empty()) {
			return {};
		}

		query_arguments_type args;

		const auto boundary_start = fmt::format("--{}", _boundary);
		const auto boundary_end = fmt::format("--{}--", _boundary);

		crlf_parser p{_data};
		auto found_boundary_end = false;
		std::string param_name;

		while (true) {
			// Find boundary.
			while (p.next_crlf()) {
				//logging::trace("LINE => {}", p.data());

				if (p.data().starts_with(boundary_end)) {
					found_boundary_end = true;
					break;
				}

				if (p.data().starts_with(boundary_start)) {
					break;
				}
			}

			if (found_boundary_end) {
				logging::trace("END OF REQUEST");
				break;
			}

			std::int64_t content_length = -1;

			// Read headers.
			// Content-Disposition is a required header. It defines the name of the parameter.
			while (p.next_crlf()) {
				if (p.data().empty()) {
					logging::trace("END OF HEADERS");
					break;
				}

				if (boost::istarts_with(p.data(), "content-disposition:")) {
					// See https://www.rfc-editor.org/rfc/rfc2045 for details about the
					// structure of MIME types.
					boost::beast::http::ext_list list{p.data().substr(std::strlen("content-disposition:"))};
					const auto type_iter = list.find("form-data");

					if (type_iter != std::end(list)) {
						for (auto&& param : type_iter->second) {
							if (param.first == "name") {
								logging::trace("PARAM = (name={}, value={})", param.first, param.second);
								param_name = param.second;
								break;
							}
						}
					}
				}
				else if (boost::istarts_with(p.data(), "content-length:")) {
					const auto slen = std::string{p.data().substr(std::strlen("content-length:"))};
					try {
						content_length = std::stoll(slen);
						logging::debug("CONTENT LENGTH = [{}]", content_length);
					}
					catch (...) {
					}
				}
				else if (boost::istarts_with(p.data(), "content-type:")) {
					if (!boost::icontains(p.data().substr(std::strlen("content-type:")), "application/octet-stream")) {
						logging::trace("INVALID CONTENT-TYPE");
						args.clear();
						return args;
					}
				}
			}

			// Read content.
			p.next_crlf(content_length);
			logging::debug("{}: CAPTURED CONTENT SIZE = [{}]", __func__, p.data().size());
			args.insert_or_assign(param_name, std::string{p.data()});
			//logging::trace("CONTENT => [{}]", p.data());
			logging::trace("END OF CONTENT");
		}

		return args;
	} // parse_multipart_form_data
} // namespace irods::http
