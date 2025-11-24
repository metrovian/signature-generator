#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <cmath>
#include <csignal>
#include <functional>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <CLI/CLI.hpp>

class command_abstract {
protected: /* command parser */
	CLI::App *command_parser_;
	std::vector<std::unique_ptr<command_abstract>> commands_;

protected: /* file */
	static int8_t read_binary(const std::string &path, std::vector<uint8_t> &binary);
	static int8_t write_binary(const std::string &path, std::vector<uint8_t> &binary);
	static int8_t read_text(const std::string &path, std::string &text);
	static int8_t write_text(const std::string &path, std::string &text);

protected: /* subcommand */
	int8_t setup_subcommand(std::unique_ptr<command_abstract> command);
	int8_t select_subcommand();

public: /* abstract */
	virtual ~command_abstract() {}

public: /* abstract */
	virtual void setup(CLI::App *parent) = 0;
	virtual void run() = 0;
};

namespace ecdsa {
enum class attack : uint8_t;
};

class command_ecdsa : public command_abstract {
protected: /* parameter */
	std::string in_;
	std::string out_;

public: /* abstract */
	virtual void setup(CLI::App *parent) override;
	virtual void run() override;
};

class command_ecdsa_private : public command_ecdsa {
protected: /* parameter */
	std::string private_pem_;
	std::string function_;
	std::unordered_map<
	    std::string,
	    std::function<std::vector<uint8_t>(const std::vector<uint8_t> &)>>
	    map_;

public: /* abstract */
	virtual void setup(CLI::App *parent) override final;
	virtual void run() override final;
};

class command_ecdsa_public : public command_ecdsa {
protected: /* parameter */
	std::string method_;
	std::unordered_map<std::string, ecdsa::attack> map_;

public: /* abstract */
	virtual void setup(CLI::App *parent) override final;
	virtual void run() override final;
};

namespace rsa {
enum class attack : uint8_t;
};

class command_rsa : public command_abstract {
protected: /* parameter */
	std::string in_;
	std::string out_;

public: /* abstract */
	virtual void setup(CLI::App *parent) override;
	virtual void run() override;
};

class command_rsa_private : public command_rsa {
protected: /* parameter */
	std::string private_pem_;
	std::string function_;
	std::unordered_map<
	    std::string,
	    std::function<std::vector<uint8_t>(const std::vector<uint8_t> &)>>
	    map_;

public: /* abstract */
	virtual void setup(CLI::App *parent) override final;
	virtual void run() override final;
};

class command_rsa_public : public command_rsa {
protected: /* parameter */
	std::string method_;
	std::unordered_map<std::string, rsa::attack> map_;

public: /* abstract */
	virtual void setup(CLI::App *parent) override final;
	virtual void run() override final;
};