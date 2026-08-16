#include <librespotc/librespotc.h>

#include <atomic>
#include <iostream>
#include <string>

namespace {

void print_usage() {
    std::cout << "Usage: harness [--name NAME] [--cache DIRECTORY]\n"
                 "Starts a Spotify Connect receiver and waits for Enter.\n";
}

} // namespace

int main(int argc, char** argv) {
    std::string device_name = "librespotclib";
    std::string cache_dir;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help") {
            print_usage();
            return 0;
        }
        if ((arg == "--name" || arg == "--cache") && i + 1 < argc) {
            const std::string value = argv[++i];
            if (arg == "--name") {
                device_name = value;
            } else {
                cache_dir = value;
            }
            continue;
        }
        print_usage();
        return 2;
    }

    std::atomic<uint64_t> frames_received{0};
    librespotc::Config config;
    config.device_name = device_name;
    config.cache_dir = cache_dir;
    config.on_audio = [&frames_received](const int16_t*, size_t frames,
                                         const librespotc::AudioFormat&) {
        frames_received.fetch_add(frames, std::memory_order_relaxed);
        return true;
    };
    config.on_track_change = [](const librespotc::TrackInfo& track) {
        std::cout << "Now playing: " << track.artist << " - " << track.title << '\n';
    };
    config.on_event = [](const librespotc::Event& event) {
        if (!event.detail.empty()) {
            std::cout << "Event: " << event.detail << '\n';
        }
    };

    auto session = librespotc::Session::create(config);
    if (!session || !session->connect()) {
        std::cerr << "Connect failed";
        if (session && !session->last_error_message().empty()) {
            std::cerr << ": " << session->last_error_message();
        }
        std::cerr << '\n';
        return 1;
    }

    std::cout << "Receiver is available as '" << device_name
              << "'. Press Enter to stop.\n";
    std::string line;
    std::getline(std::cin, line);
    session->disconnect();
    std::cout << "Received " << frames_received.load() << " PCM frames.\n";
    return 0;
}
