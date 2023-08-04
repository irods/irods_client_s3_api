#include "authentication.hpp"
#include "hmac.hpp"
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <irods/rodsKeyWdDef.h>
#include <sstream>
#include <boost/algorithm/string.hpp>
#include <irods/switch_user.h>
#include <irods/rcMisc.h>

namespace
{

    std::string uri_encode(const std::string_view sv)
    {
        std::stringstream s;
        std::ios state(nullptr);
        state.copyfmt(s);
        for (auto c : sv) {
            bool encode = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                          boost::is_any_of("-_~.")(c);
            if (!encode) {
                // Interestingly, most hex-encoded values in the amazon api tend to be lower case,
                // except for this.
                s << '%' << std::uppercase << std::hex << std::setw(2) << std::setfill('0') << (int) c;
                s.copyfmt(state);
            }
            else {
                s << c;
            }
        }
        return s.str();
    }

    std::string
    get_user_signing_key(const std::string_view secret_key, const std::string_view date, const std::string_view region)
    {
        // Hate it when amazon gives me homework
        // during implementation of their protocol
        std::cout << "date time component is " << date << std::endl;
        auto date_key = irods::s3::authentication::hmac_sha_256(std::string("AWS4").append(secret_key), date);
        auto date_region_key = irods::s3::authentication::hmac_sha_256(date_key, region);
        // 'date region service key'
        auto date_region_service_key = irods::s3::authentication::hmac_sha_256(date_region_key, "s3");
        return irods::s3::authentication::hmac_sha_256(date_region_service_key, "aws4_request");
    }

    // TODO when this is working, we can improve performance by reusing the same stringstream where possible.

    // Turn the url into the 'canon form'
    std::string canonicalize_url(const static_buffer_request_parser& request, const boost::urls::url_view& url)
    {
        std::stringstream result;
        // result << request.get().at("Host");
        for (const auto& i : url.segments()) {
            result << '/' << uri_encode(i); // :shrug:
        }
        return result.str();
    }

    bool should_include_header(const std::string_view sv)
    {
        return sv.starts_with("X-Amz") || sv.starts_with("x-amz") || sv == "Host" || sv == "Content-Type";
    }
    std::string to_lower(const std::string_view sv)
    {
        std::string r;
        for (auto i : sv) {
            r.push_back(tolower(i));
        }
        return r;
    }
    std::string canonicalize_request(
        const static_buffer_request_parser& request,
        const boost::urls::url_view& url,
        const std::vector<std::string>& signed_headers)
    {
        // At various points the signature process wants various fields to be sorted.
        // so reusing this can at least avoid some of the duplicate allocations and such
        std::vector<std::string_view> sorted_fields;

        std::stringstream result;

        std::ios state(nullptr);
        state.copyfmt(result);

        result << request.get().method_string() << '\n';
        result.copyfmt(result); // re store former formatting
        result << canonicalize_url(request, url) << '\n';
        // Canonicalize query string
        {
            bool first = true;
            // Changing it to a pair enables us to sort easily.
            std::vector<std::pair<std::string, std::string>> params;
            std::transform(
                url.encoded_params().begin(), url.encoded_params().end(), std::back_inserter(params), [](const auto &a) {
                    if (a.has_value) {
                        return std::make_pair<std::string, std::string>(uri_encode(a.key), uri_encode(a.value));
                    }
                    return std::make_pair(uri_encode(a.key), std::string(""));
                });
            std::sort(params.begin(), params.end());
            for (const auto& param : params) {
                result << (first ? "" : "&") << param.first;
                result << '=' << param.second;

                first = false;
            }
        }
        result << '\n';

        for (const auto& header : request.get()) {
            if (should_include_header(header.name_string()) ||
                std::find(signed_headers.begin(), signed_headers.end(), to_lower(header.name_string())) !=
                    signed_headers.end())
            {
                sorted_fields.emplace_back(header.name_string().data(), header.name_string().length());
            }
        }

        // Produce the 'canonical headers'

        // They mix cases of headers :)
        // I hate it
        std::sort(sorted_fields.begin(), sorted_fields.end(), [](const auto& lhs, const auto& rhs) {
            const auto result = std::mismatch(
                lhs.cbegin(),
                lhs.cend(),
                rhs.cbegin(),
                rhs.cend(),
                [](const unsigned char lhs, const unsigned char rhs) { return tolower(lhs) == tolower(rhs); });

            return result.second != rhs.cend() &&
                   (result.first == lhs.cend() || tolower(*result.first) < tolower(*result.second));
        });
        for (auto& i : sorted_fields) {
            std::cerr << i << ",";
        }
        std::cerr << '\n';
        for (const auto& field : sorted_fields) {
            auto val = static_cast<std::string>(request.get().at(boost::string_view(field.data(), field.length())));
            std::string key(field);
            std::transform(key.begin(), key.end(), key.begin(), tolower);
            boost::trim(val);
            result << key << ':';
            result.copyfmt(state);
            result << val << '\n';
        }
        result << "\n";

        sorted_fields.clear();

        // and the signed header list

        for (const auto& hd : signed_headers) {
            sorted_fields.push_back(hd);
        }
        std::sort(sorted_fields.begin(), sorted_fields.end());
        {
            bool first = true;
            for (const auto& i : sorted_fields) {
                result << (first ? "" : ";") << i;
                first = false;
            }
            result.copyfmt(state);
            result << '\n';
        }

        //and the payload signature

        if (auto req = request.get().find("X-Amz-Content-SHA256"); req != request.get().end()) {
            result << req->value();
        }
        else {
            result << "UNSIGNED-PAYLOAD";
        }

        return result.str();
    }

    std::string string_to_sign(
        const static_buffer_request_parser& request,
        const boost::urls::url_view& url,
        const std::string_view date,
        const std::string_view region,
        const std::string_view canonical_request)
    {
        std::stringstream result;
        result << "AWS4-HMAC-SHA256\n";
        result << request.get().at("X-Amz-Date") << '\n';
        result << date << '/' << region << "/s3/aws4_request\n";
        result << irods::s3::authentication::hex_encode(irods::s3::authentication::hash_sha_256(canonical_request));
        return result.str();
    }
} //namespace
bool irods::s3::authentication::authenticates(
    rcComm_t& conn,
    const static_buffer_request_parser& request,
    const boost::urls::url_view& url)
{
    std::vector<std::string> auth_fields, credential_fields, signed_headers;
    // should be equal to something like
    // [ 'AWS4-SHA256-HMAC Credential=...', 'SignedHeaders=...', 'Signature=...']
    //
    boost::split(auth_fields, request.get().at("Authorization"), boost::is_any_of(","));

    // Strip the names and such
    for (auto& field : auth_fields) {
        field = field.substr(field.find('=') + 1);
    }

    // Break up the credential field.
    boost::split(credential_fields, auth_fields[0], boost::is_any_of("/"));

    auto& access_key_id = credential_fields[0];
    auto& date = credential_fields[1];
    auto& region = credential_fields[2];
    // Look, covering my bases here seems prudent.
    auto& aws_service = credential_fields[3];

    auto& signature = auth_fields[2];

    boost::split(signed_headers, auth_fields[1], boost::is_any_of(";"));

    auto canonical_request = canonicalize_request(request, url, signed_headers);
    std::cout << "Canon request==========================" << std::endl;
    std::cout << canonical_request << '\n';
    std::cout << "=======================================" << std::endl;

    auto sts = string_to_sign(request, url, date, region, canonical_request);

    std::cout << sts << '\n';
    std::cout << "=========================" << std::endl;

    auto irods_user = irods::s3::authentication::get_iRODS_user(&conn, access_key_id).value();
    auto signing_key = get_user_signing_key(
        irods::s3::authentication::get_user_secret_key(&conn, access_key_id).value(), date, region);
    auto computed_signature = hex_encode(hmac_sha_256(signing_key, sts));

    SwitchUserInput input{};
    std::strcpy(input.username, irods_user.c_str());
    std::strcpy(input.zone, conn.clientUser.rodsZone);
    addKeyVal(&input.options, KW_CLOSE_OPEN_REPLICAS, "");

    if (const auto ec = rc_switch_user(&conn, &input); ec < 0) {
        std::cout << "Faied to switch users! code [" << ec << "]" << std::endl;
    }

    std::cout << "Computed: [" << computed_signature << "]";

    std::cout << "\nActual Signature: [" << signature << "]" << std::endl;

    return computed_signature == signature;
}
