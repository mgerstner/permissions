// Linux
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// local headers
#include "utility.h"

// C++
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

void splitWords(const std::string &input, std::vector<std::string> &words) {
    std::stringstream ss;
    std::string word;

    words.clear();
    ss.str(input);

    // read whitespace separated words
    while (!ss.fail()) {
        ss >> word;

        if (!ss.fail()) {
            words.emplace_back(word);
        }
    }
}

std::string getSubprocessOutput(const std::vector<std::string> &cmdline, int &code) {
    // we use this exit code to indicate pre-exec errors
    constexpr int STATUS_INTERNAL_ERROR = 125;
    code = STATUS_INTERNAL_ERROR;
    int pipe_ends[2];
    if (::pipe(pipe_ends) != 0) {
        throw std::runtime_error{"failed to create pipe"};
    }

    if (const auto pid = fork(); pid == 0) {
        // child process

        // close the read end of the pipe
        ::close(pipe_ends[0]);
        // redirect stdout to the pipe
        if (!::dup2(pipe_ends[1], STDOUT_FILENO)) {
            _exit(STATUS_INTERNAL_ERROR);
        }

        // close the now unnecessary copy of the write end of the pipe
        ::close(pipe_ends[1]);

        std::vector<const char*> c_cmdline;
        for (const auto &str: cmdline) {
            c_cmdline.push_back(str.c_str());
        }
        // the argument list is terminated by a NULL ptr.
        c_cmdline.push_back(nullptr);
        ::execvpe(c_cmdline[0], const_cast<char *const*>(c_cmdline.data()), environ);
        // should not be reached, if new executable couldn't be run, exit with
        // the internal error code again
        _exit(STATUS_INTERNAL_ERROR);
    } else {
        // parent process

        // close the write end of the pipe
        ::close(pipe_ends[1]);

        std::string ret;
        size_t read_bytes = 0;
        constexpr size_t IO_SIZE = 512;

        // read the child's stdout until we encounter an EOF or error condition
        while (true) {
            ret.resize(read_bytes + IO_SIZE);
            if (const auto res = read(pipe_ends[0], ret.data() + read_bytes, IO_SIZE); res <= 0) {
                // error while reading or EOF encountered, stop the loop
                ret.resize(read_bytes);
                break;
            } else {
                // we got some additional data
                read_bytes += static_cast<size_t>(res);
            }
        }

        int status = 0;
        if (waitpid(pid, &status, 0) < 0) {
            throw std::runtime_error{"failed to wait on child"};
        }

        if (!WIFEXITED(status)) {
            throw std::runtime_error{"child process exited abnormally"};
        }

        code = WEXITSTATUS(status);

        return ret;
    }
}

void FileDesc::close() {
    if (!valid())
        return;

    if (::close(m_fd) != 0) {
        std::cerr << "Closing FD " << m_fd << ": " << strerror(errno) << std::endl;
    }

    invalidate();
}

std::string FileDesc::path() const {
    std::string linkpath(PATH_MAX, '\0');
    auto procpath = std::string("/proc/self/fd/") + std::to_string(this->get());

    ssize_t l = ::readlink(procpath.c_str(), &linkpath[0], linkpath.size());
    if (l > 0) {
        linkpath.resize(std::min(static_cast<size_t>(l), linkpath.size()));
    } else {
        linkpath = "ancestor";
    }

    return linkpath;
}

FileCapabilities::FileCapabilities(cap_t raw) :
        m_caps{raw, ::cap_free} {
}

bool FileCapabilities::operator==(const FileCapabilities &other) const {
    if (!hasCaps() && !other.hasCaps())
        // if both lack capabilities then compare to true
        return true;

    if (hasCaps() != other.hasCaps())
        // if only one is lacking capabilities then compare to false
        return false;

    // otherwise ask the lib
    return ::cap_compare(m_caps.get(), other.m_caps.get()) == 0;
}

FileCapabilities FileCapabilities::copy() const {
    return FileCapabilities{::cap_dup(m_caps.get())};
}

bool FileCapabilities::setFromText(const std::string &text) {
    m_caps.reset(::cap_from_text(text.c_str()));

    if (!hasCaps()) {
        m_last_errno = errno;
        return false;
    }

    return true;
}

std::string FileCapabilities::toText() const {
    if (!hasCaps())
        return "";

    auto text = ::cap_to_text(m_caps.get(), nullptr);

    if (!text)
        return "";

    auto ret = std::string(text);

    ::cap_free(text);

    return ret;
}

bool FileCapabilities::setFromFile(const std::string &path) {
    m_caps.reset(::cap_get_file(path.c_str()));

    m_last_errno = m_caps ? 0 : errno;

    return m_caps || m_last_errno == ENODATA;
}

std::string FileCapabilities::lastErrorText() const {
    switch(m_last_errno) {
            default:
                return std::string{"failed to get capabilities: "} + std::strerror(m_last_errno);
            case 0:
                return "no error";
            // we get EBADF for files that don't support capabilities, e.g. sockets or FIFOs
            case EBADF:
                return "cannot assign capabilities for this kind of file";
            case EOPNOTSUPP:
                return "no support for capabilities on kernel or file system";
    }
}

bool FileCapabilities::applyToFD(int fd) const {
    if (::cap_set_fd(fd, m_caps.get()) != 0) {
        return false;
    }

    return true;
}

FileAcl::FileAcl(mode_t mode) :
        m_acl{::acl_from_mode(mode), ::acl_free} {
}

FileAcl::FileAcl(acl_t raw) :
        m_acl{raw, ::acl_free} {
}

FileAcl FileAcl::copy() const {
    return FileAcl{::acl_dup(const_cast<acl_t>(m_acl.get()))};
}

bool FileAcl::setFromText(const std::string &text) {
    m_acl.reset(::acl_from_text(text.c_str()));

    return valid();
}

bool FileAcl::setFromFile(const std::string &path) {
    m_acl.reset(::acl_get_file(path.c_str(), ACL_TYPE_ACCESS));

    return valid();
}

bool FileAcl::applyToFile(const std::string &path) const {
    return ::acl_set_file(path.c_str(), ACL_TYPE_ACCESS, m_acl.get()) == 0;
}

bool FileAcl::setBasicEntries(mode_t mode) {
    if (!valid()) {
        errno = EINVAL;
        return false;
    }

    FileAcl basic{mode};

    if (!basic.valid())
        return false;

    acl_entry_t entry;
    if (::acl_get_entry(basic.raw(), ACL_FIRST_ENTRY, &entry) != 1)
        return false;

    do {
        acl_entry_t new_entry;
        auto ptr = raw();
        if (::acl_create_entry(&ptr, &new_entry) != 0)
            return false;
        checkForRealloc(ptr);
        if (::acl_copy_entry(new_entry, entry) != 0)
            return false;
    } while (::acl_get_entry(basic.raw(), ACL_NEXT_ENTRY, &entry) == 1);

    return true;
}

bool FileAcl::tryCalcMask() {
    auto ptr = raw();
    const auto ret = ::acl_calc_mask(&ptr) == 0;

    checkForRealloc(ptr);

    return ret;
}

void FileAcl::checkForRealloc(acl_t ptr) {
    // some libacl functions take a pointer to pointer (acl_t*), because they
    // may realloc the pointed-to memory as a side effect.
    // in this case we must reflect the change in our managed m_acl
    // unique_ptr.
    if (ptr != m_acl.get()) {
        m_acl.release();
        m_acl.reset(ptr);
    }
}

bool FileAcl::verify() const {
    return ::acl_valid(m_acl.get()) == 0;
}

std::string FileAcl::toText() const {
    if (!valid())
        return "";

    auto text = ::acl_to_any_text(m_acl.get(), nullptr, ' ', 0);
    std::string ret{text};
    ::acl_free(text);
    return ret;
}

bool FileAcl::isBasicACL() const {
    if (!valid())
        // what to do here? would require an exception, actually
        return true;

    return ::acl_equiv_mode(m_acl.get(), nullptr) == 0;
}

bool FileAcl::operator==(const FileAcl &other) const {
    if (valid() != other.valid())
        return false;
    else if (!valid() && !other.valid())
        return true;

    return ::acl_cmp(m_acl.get(), other.m_acl.get()) == 0;
}

// vim: et ts=4 sts=4 sw=4 :
