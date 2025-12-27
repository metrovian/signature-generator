#include "command/abstract.h"

int8_t command_abstract::read_binary(const std::string &path, std::vector<uint8_t> &binary) {
	std::ifstream ifs(path, std::ios::binary);
	if (ifs.is_open() == false) {
		return -1;
	}

	binary.clear();
	binary.resize(static_cast<size_t>(std::filesystem::file_size(path)));
	ifs.read(reinterpret_cast<char *>(binary.data()), binary.size());
	if (ifs.fail() == true) {
		return -2;
	}

	return 0;
}

int8_t command_abstract::write_binary(const std::string &path, std::vector<uint8_t> &binary) {
	std::ofstream ofs(path, std::ios::binary);
	if (ofs.is_open() == false) {
		return -1;
	}

	ofs.write(reinterpret_cast<const char *>(binary.data()), binary.size());
	if (ofs.fail() == true) {
		return -2;
	}

	return 0;
}

int8_t command_abstract::read_text(const std::string &path, std::string &text) {
	std::ifstream ifs(path);
	if (ifs.is_open() == false) {
		return -1;
	}

	std::ostringstream oss;
	oss << ifs.rdbuf();
	if (ifs.fail() == true) {
		return -2;
	}

	text = oss.str();
	return 0;
}

int8_t command_abstract::write_text(const std::string &path, std::string &text) {
	std::ofstream ofs(path);
	if (ofs.is_open() == false) {
		return -1;
	}

	ofs << text;
	if (ofs.fail() == true) {
		return -2;
	}

	return 0;
}

int8_t command_abstract::setup_subcommand(std::unique_ptr<command_abstract> command) {
	command->setup(command_parser_);
	commands_.emplace_back(std::move(command));
	return 0;
}

int8_t command_abstract::select_subcommand() {
	for (auto &command : command_parser_->get_subcommands()) {
		if (command->parsed() == true) {
			return 1;
		}
	}

	return 0;
}