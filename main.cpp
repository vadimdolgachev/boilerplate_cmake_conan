#include <iostream>

#include <fmt/core.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/regex.hpp>
#include <boost/algorithm/string/replace.hpp>

#include "root_certificates.hpp"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>


struct Uri {
    std::string host;
    std::string target;
    std::string port;

    static Uri parse(const char *url) {
        Uri uri;
        const boost::regex rx("(http|https)://([^/ :]+):?([^/ ]*)(/?[^ #?]*)\\x3f?([^ #]*)#?([^ ]*)");
        boost::cmatch match;
        if (regex_match(url, match, rx)) {
            const auto protocol = match[1].str();
            uri.host = match[2].str();
            uri.port = match[3].str();
            if (uri.port.empty()) {
                uri.port = (protocol == "https") ? "443" : "80";
            }
            const auto path = match[4].length() > 0 ? match[4].str() : "/";
            const auto query = match[5].str();
            uri.target = path + (query.empty() ? "" : "?" + query);
        }
        return uri;
    }
};

class Session : public std::enable_shared_from_this<Session> {
    constexpr static int HTTT_VERSION = 11;
    constexpr static auto TIMEOUT_SECS = std::chrono::seconds(30);
    tcp::resolver resolver;
    beast::ssl_stream<beast::tcp_stream> stream;
    beast::flat_buffer buffer;
    boost::optional<http::request<http::empty_body>> request;
    http::response<http::string_body> response;

public:
    explicit Session(net::any_io_executor ex, ssl::context &ctx)
        : resolver(ex),
          stream(ex, ctx) {
    }

    void get(const Uri &uri) {
        fmt::print("get {}{}\n", uri.host, uri.target);

        if (!SSL_set_tlsext_host_name(stream.native_handle(), uri.host.c_str())) {
            beast::error_code ec{static_cast<int>(::ERR_get_error()),
                                 net::error::get_ssl_category()};
            std::cerr << ec.message() << "\n";
            return;
        }

        request = http::request<http::empty_body>(http::verb::get,
                                                  uri.target,
                                                  HTTT_VERSION);
        request->set(http::field::host, uri.host);

        resolver.async_resolve(uri.host,
                               uri.port,
                               beast::bind_front_handler(&Session::onResolve,
                                                         shared_from_this()));
    }

private:
    void onResolve(beast::error_code ec,
                   const tcp::resolver::results_type &results) {
        if (ec) {
            return onFail(ec, "resolve");
        }

        for (auto i : results) {
            fmt::print("onResolve={}:{} {}\n", i.host_name(), i.service_name(), i.endpoint().address().to_string());
        }

        beast::get_lowest_layer(stream).expires_after(TIMEOUT_SECS);
        beast::get_lowest_layer(stream).async_connect(results,
                                                      beast::bind_front_handler(&Session::onConnect,
                                                                                shared_from_this()));
    }

    void onConnect(beast::error_code ec,
                   const tcp::resolver::results_type::endpoint_type &endpoint) {
        if (ec) {
            return onFail(ec, "connect");
        }

        fmt::print("onConnect {} {}{} {}\n", request->method_string().data(),
                   boost::replace_all_copy((*request)[http::field::host].to_string(), "\r\n", "").data(),
                   request->target().data(),
                   endpoint.address().to_string());

        stream.async_handshake(ssl::stream_base::client,
                               beast::bind_front_handler(&Session::onHandshake,shared_from_this()));
    }

    void onHandshake(beast::error_code ec) {
        if (ec) {
            return onFail(ec, "handshake");
        }

        fmt::print("onHandshake\n");

        beast::get_lowest_layer(stream).expires_after(TIMEOUT_SECS);
        http::async_write(stream,
                          *request,
                          beast::bind_front_handler(&Session::onWrite, shared_from_this()));
    }

    void onWrite(beast::error_code ec, std::size_t bytes) {
        if (ec) {
            return onFail(ec, "write");
        }

        fmt::print("onWrite bytes={}, {}\n", bytes);

        http::async_read(stream,
                         buffer,
                         response,
                         beast::bind_front_handler(&Session::onRead,
                                                   shared_from_this()));
    }

    void onRead(beast::error_code ec, std::size_t bytes) {
        if (ec) {
            return onFail(ec, "read");
        }

        fmt::print("onRead bytes={}\n", bytes);

        std::string_view body = response.body();
        fmt::print("body={}\n", body.substr(0,
                                            std::min(static_cast<std::string::size_type>(100),
                                                     body.length())));
        beast::get_lowest_layer(stream).expires_after(TIMEOUT_SECS);
    }

    static void onFail(beast::error_code ec, char const *what) {
        fmt::print("onFail what={}, message={}\n", what, ec.message());
    }
};


int main(int argc, char *argv[]) {
    const Uri &uri = Uri::parse(argc > 1 ? argv[1] : "https://www.google.com");
    fmt::print("host={} ,port={}, target={}\n",
               uri.host, uri.port, uri.target);
    ssl::context sslContext{ssl::context::tlsv12_client};
    load_root_certificates(sslContext);
    sslContext.set_verify_mode(ssl::verify_peer);
    net::io_context ioc;
    std::make_shared<Session>(net::make_strand(ioc), sslContext)->get(uri);
    ioc.run();
    return EXIT_SUCCESS;
}
