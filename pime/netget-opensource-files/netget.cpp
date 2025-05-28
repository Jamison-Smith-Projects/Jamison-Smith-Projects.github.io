#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <memory>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>

// Define version constant
const std::string VERSION = "1.0";

class Curl {
public:
    Curl() {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ctx_ = SSL_CTX_new(TLS_client_method());
        if (!ctx_) {
            throw std::runtime_error("Failed to create SSL context");
        }
    }

    ~Curl() {
        cleanup();
    }

    void download(const std::string& url) {
        try {
            parse_url(url);
            connect_to_host();
            setup_ssl();
            send_request();
            auto response = receive_response();
            process_response(response);
        } catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            cleanup();
            throw;
        }
    }

    void set_output(const std::string& filename) { output_file_ = filename; }
    void set_insecure(bool insecure) { insecure_ = insecure; }
    void set_follow_redirects(bool follow) { follow_redirects_ = follow; }
    void set_verbose(bool verbose) { verbose_ = verbose; }
    void set_silent(bool silent) { silent_ = silent; }
    void add_header(const std::string& header) { headers_.push_back(header); }
    void set_data(const std::string& data) { data_ = data; }
    void set_method(const std::string& method) { method_ = method; }
    std::string get_method() const { return method_; }  // Added get_method()

private:
    std::string host_;
    std::string path_;
    int port_ = 443;
    int socket_fd_ = -1;
    SSL_CTX* ctx_ = nullptr;
    SSL* ssl_ = nullptr;
    std::string output_file_;
    bool insecure_ = false;
    bool follow_redirects_ = false;
    bool verbose_ = false;
    bool silent_ = false;
    std::vector<std::string> headers_;
    std::string data_;
    std::string method_ = "GET";
    int max_redirects_ = 10;
    int redirect_count_ = 0;

    void cleanup() {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (socket_fd_ >= 0) {
            close(socket_fd_);
            socket_fd_ = -1;
        }
    }

    void parse_url(const std::string& url) {
        size_t proto_pos = url.find("://");
        if (proto_pos == std::string::npos) {
            throw std::runtime_error("Invalid URL format");
        }

        std::string protocol = url.substr(0, proto_pos);
        if (protocol != "http" && protocol != "https") {
            throw std::runtime_error("Only HTTP/HTTPS protocols are supported");
        }

        std::string rest = url.substr(proto_pos + 3);
        size_t path_pos = rest.find('/');
        if (path_pos == std::string::npos) {
            host_ = rest;
            path_ = "/";
        } else {
            host_ = rest.substr(0, path_pos);
            path_ = rest.substr(path_pos);
        }

        size_t port_pos = host_.find(':');
        if (port_pos != std::string::npos) {
            port_ = std::stoi(host_.substr(port_pos + 1));
            host_ = host_.substr(0, port_pos);
        } else {
            port_ = (protocol == "https") ? 443 : 80;
        }
    }

    void connect_to_host() {
        if (verbose_) {
            std::cerr << "* Trying " << host_ << "..." << std::endl;
        }

        struct hostent* host = gethostbyname(host_.c_str());
        if (!host) {
            throw std::runtime_error("Failed to resolve host: " + host_);
        }

        socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (socket_fd_ < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Set timeout
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        setsockopt(socket_fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(socket_fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port_);
        addr.sin_addr = *((struct in_addr*)host->h_addr);

        if (connect(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            throw std::runtime_error("Failed to connect to " + host_ + ":" + std::to_string(port_));
        }

        if (verbose_) {
            std::cerr << "* Connected to " << host_ << " (" << inet_ntoa(addr.sin_addr) 
                      << ") port " << port_ << std::endl;
        }
    }

    void setup_ssl() {
        if (port_ != 443) return; // Only setup SSL for HTTPS

        ssl_ = SSL_new(ctx_);
        if (!ssl_) {
            throw std::runtime_error("Failed to create SSL connection");
        }

        SSL_set_fd(ssl_, socket_fd_);
        SSL_set_tlsext_host_name(ssl_, host_.c_str());

        if (insecure_) {
            SSL_set_verify(ssl_, SSL_VERIFY_NONE, nullptr);
            if (verbose_) {
                std::cerr << "* SSL certificate verification disabled" << std::endl;
            }
        }

        if (SSL_connect(ssl_) != 1) {
            throw std::runtime_error("SSL handshake failed: " + get_ssl_error());
        }

        if (verbose_) {
            std::cerr << "* SSL connection using " << SSL_get_cipher(ssl_) << std::endl;
        }
    }

    void send_request() {
        std::stringstream request;
        request << method_ << " " << path_ << " HTTP/1.1\r\n";
        request << "Host: " << host_ << "\r\n";
        request << "User-Agent: curl/" << VERSION << "\r\n";
        request << "Accept: */*\r\n";

        if (!data_.empty()) {
            request << "Content-Length: " << data_.length() << "\r\n";
            request << "Content-Type: application/x-www-form-urlencoded\r\n";
        }

        for (const auto& header : headers_) {
            request << header << "\r\n";
        }

        request << "Connection: close\r\n\r\n";

        if (!data_.empty()) {
            request << data_;
        }

        std::string request_str = request.str();
        if (verbose_) {
            std::cerr << "> " << method_ << " " << path_ << " HTTP/1.1" << std::endl;
            std::cerr << "> Host: " << host_ << std::endl;
            std::cerr << "> User-Agent: curl/" << VERSION << std::endl;
            std::cerr << "> Accept: */*" << std::endl;
            if (!data_.empty()) {
                std::cerr << "> Content-Length: " << data_.length() << std::endl;
                std::cerr << "> Content-Type: application/x-www-form-urlencoded" << std::endl;
            }
            for (const auto& header : headers_) {
                std::cerr << "> " << header << std::endl;
            }
            std::cerr << "> " << std::endl;
            if (!data_.empty() && verbose_) {
                std::cerr << "> " << data_ << std::endl;
            }
        }

        int result;
        if (ssl_) {
            result = SSL_write(ssl_, request_str.c_str(), request_str.length());
        } else {
            result = write(socket_fd_, request_str.c_str(), request_str.length());
        }

        if (result <= 0) {
            throw std::runtime_error("Failed to send request: " + get_ssl_error());
        }
    }

    std::string receive_response() {
        std::string response;
        char buf[4096];
        int bytes;

        while (true) {
            if (ssl_) {
                bytes = SSL_read(ssl_, buf, sizeof(buf));
            } else {
                bytes = read(socket_fd_, buf, sizeof(buf));
            }

            if (bytes > 0) {
                response.append(buf, bytes);
            } else if (bytes == 0) {
                break; // Connection closed
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    throw std::runtime_error("Timeout while waiting for response");
                }
                throw std::runtime_error("Error reading response: " + get_ssl_error());
            }
        }

        return response;
    }

    void process_response(const std::string& response) {
        size_t header_end = response.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            throw std::runtime_error("Invalid HTTP response format");
        }

        std::string headers = response.substr(0, header_end);
        std::string body = response.substr(header_end + 4);

        if (verbose_) {
            std::cerr << "< " << headers << std::endl;
            std::cerr << "< " << std::endl;
        }

        // Check HTTP status
        if (headers.substr(0, 12) != "HTTP/1.1 200" && 
            headers.substr(0, 12) != "HTTP/1.1 301" && 
            headers.substr(0, 12) != "HTTP/1.1 302") {
            size_t status_end = headers.find("\r\n");
            if (!silent_) {
                std::cerr << "HTTP request failed: " << headers.substr(0, status_end) << std::endl;
            }
            throw std::runtime_error("HTTP request failed");
        }

        // Handle redirects
        if (follow_redirects_ && 
            (headers.substr(0, 12) == "HTTP/1.1 301" || 
             headers.substr(0, 12) == "HTTP/1.1 302")) {
            size_t location_pos = headers.find("Location: ");
            if (location_pos != std::string::npos) {
                size_t location_end = headers.find("\r\n", location_pos);
                std::string new_url = headers.substr(location_pos + 10, location_end - (location_pos + 10));
                
                if (redirect_count_++ >= max_redirects_) {
                    throw std::runtime_error("Too many redirects (max " + std::to_string(max_redirects_) + ")");
                }

                if (verbose_) {
                    std::cerr << "* Redirecting to " << new_url << " (" << redirect_count_ << "/" << max_redirects_ << ")" << std::endl;
                }

                cleanup();
                download(new_url);
                return;
            }
        }

        // Output the body
        if (!output_file_.empty()) {
            std::ofstream out(output_file_, std::ios::binary);
            if (!out) {
                throw std::runtime_error("Failed to open output file: " + output_file_);
            }
            out.write(body.c_str(), body.size());
            if (!silent_) {
                std::cout << "Downloaded " << body.size() << " bytes to " << output_file_ << std::endl;
            }
        } else {
            std::cout << body;
        }
    }

    std::string get_ssl_error() {
        unsigned long err = ERR_get_error();
        if (err) {
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            return buf;
        }
        return strerror(errno);
    }
};

void show_help() {
    std::cout << "Usage: pime-netget [options...] <url>\n"
              << "Options:\n"
              << "  -X, --request METHOD  HTTP method (GET, POST, etc.)\n"
              << "  -H, --header HEADER   Add a custom header\n"
              << "  -d, --data DATA       Send data in request body\n"
              << "  -o, --output FILE     Write output to FILE\n"
              << "  -L, --location        Follow redirects\n"
              << "  -k, --insecure        Skip SSL verification\n"
              << "  -v, --verbose         Show verbose output\n"
              << "  -s, --silent          Silent mode\n"
              << "  --help                Show this help\n"
              << "Examples:\n"
              << "  cupime-netgetrl https://example.com\n"
              << "  pime-netget -o file.txt https://example.com\n"
              << "  pime-netget -X POST -d 'data' https://example.com\n"
              << "  pime-netget https://example.com | bash\n";
}

int main(int argc, char* argv[]) {
    static struct option long_options[] = {
        {"request", required_argument, 0, 'X'},
        {"header", required_argument, 0, 'H'},
        {"data", required_argument, 0, 'd'},
        {"output", required_argument, 0, 'o'},
        {"location", no_argument, 0, 'L'},
        {"insecure", no_argument, 0, 'k'},
        {"verbose", no_argument, 0, 'v'},
        {"silent", no_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    Curl curl;
    std::string url;
    bool pipe_to_bash = false;

    // Check if we're piping to bash
    for (int i = 1; i < argc; i++) {
        if (std::string(argv[i]) == "|") {
            pipe_to_bash = true;
            break;
        }
    }

    int opt;
    while ((opt = getopt_long(argc, argv, "X:H:d:o:Lkvs", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'X':
                curl.set_method(optarg);
                break;
            case 'H':
                curl.add_header(optarg);
                break;
            case 'd':
                curl.set_data(optarg);
                if (curl.get_method() == "GET") {
                    curl.set_method("POST");
                }
                break;
            case 'o':
                curl.set_output(optarg);
                break;
            case 'L':
                curl.set_follow_redirects(true);
                break;
            case 'k':
                curl.set_insecure(true);
                break;
            case 'v':
                curl.set_verbose(true);
                break;
            case 's':
                curl.set_silent(true);
                break;
            case 'h':
                show_help();
                return 0;
            default:
                show_help();
                return 1;
        }
    }

    if (optind >= argc) {
        std::cerr << "Error: URL argument missing\n";
        show_help();
        return 1;
    }

    url = argv[optind];

    try {
        if (pipe_to_bash) {
            // Save to temporary file
            std::string temp_file = "/tmp/curl_pipe_" + std::to_string(getpid());
            curl.set_output(temp_file);
            curl.download(url);
            
            // Execute with bash
            std::string command = "bash " + temp_file;
            system(command.c_str());
            
            // Cleanup
            unlink(temp_file.c_str());
        } else {
            curl.download(url);
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "curl: error: " << e.what() << std::endl;
        return 1;
    }
}