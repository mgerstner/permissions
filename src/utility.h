#ifndef CHKSTAT_UTILITY_H
#define CHKSTAT_UTILITY_H

// POSIX
#include <sys/capability.h>
#include <sys/stat.h>

// third party
#include <tclap/CmdLine.h>

// C++
#include <cctype>
#include <cstring>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

/// SwitchArg that can be programmatically set.
/**
 * TCLAP::SwitchArg doesn't offer a public API to programmatically change the
 * switch's value. Therefore this specialization provides an additional method
 * to make this possible.
 **/
class SwitchArgRW :
        public TCLAP::SwitchArg {
public:
    SwitchArgRW(
            const std::string &flag,
            const std::string &name,
            const std::string &desc,
            TCLAP::CmdLineInterface &parser) :
            TCLAP::SwitchArg{flag, name, desc, parser} {
    }

    void setValue(bool val) {
        _value = val;
        // this is used for isSet(), _value only for getValue(), so
        // sync both.
        _alreadySet = val;
    }
};

/// ValueArg with sane const semantics.
/**
 * The TCLAP::ValueArg is missing accessors that allow access the contained
 * value in const contexts. Sadly there was no release of TCLAP in a long
 * time, the upstream master branch contains suitable fixes already, however.
 * This is just a small wrapper to fix this situation.
 **/
template <typename T>
class SaneValueArg :
        public TCLAP::ValueArg<T> {
public:
    SaneValueArg(
            const std::string &flag,
            const std::string &name,
            const std::string &desc,
            bool req,
            T value,
            const std::string &typeDesc,
            TCLAP::CmdLineInterface &parser) :
            TCLAP::ValueArg<T>{flag, name, desc, req, value, typeDesc, parser} {
    }

    const T& getValue() const {
        return this->_value;
    }

    T& getValue() {
        return this->_value;
    }
};

/// `isspace()` has overloads which gives trouble with template argument deduction, therefore provide a wrapper.
inline bool chkspace(char c) { return std::isspace(c); }

inline bool chkslash(char c) { return c == '/'; }

/// Remove certain leading characters from the given string (by default whitespace characters).
template <typename UNARY = bool(char)>
inline void lstrip(std::string &s, UNARY f = chkspace) {
    auto nonmatch_it = s.end();

    for (auto it = s.begin(); it != s.end(); it++) {
        if (!f(*it)) {
            nonmatch_it = it;
            break;
        }
    }

    s = s.substr(static_cast<size_t>(nonmatch_it - s.begin()));
}

/// Remove certain trailing characters from the given string (by default: whitespace characters).
template <typename UNARY = bool(char)>
inline void rstrip(std::string &s, UNARY f = chkspace) {
    while (!s.empty() && f(*s.rbegin()))
        s.pop_back();
}

/// Remove certain leading and trailing characters from the given string (by default: whitespace characters).
template <typename UNARY = bool(char)>
void strip(std::string &s, UNARY f = chkspace) {
    lstrip(s, f);
    rstrip(s, f);
}

/// Checks whether the given string has the given prefix.
inline bool hasPrefix(const std::string &s, const std::string &prefix) {
    return s.substr(0, prefix.length()) == prefix;
}

/// Checks whether the given string has the given suffix.
inline bool hasSuffix(const std::string_view &s, const std::string &suffix) {
    if (suffix.length() > s.length())
        return false;

    return s.substr(s.length() - suffix.length()) == suffix;
}

/// Returns whether the given iterable sequence contains the given element `val`.
template <typename T, typename SEQ>
bool matchesAny(const T &val, const SEQ &seq) {
    for (const auto &e: seq) {
        if (val == e)
            return true;
    }

    return false;
}

/// Splits up the `input` string into whitespace separated words and stores them in `words`.
void splitWords(const std::string &input, std::vector<std::string> &words);

template <typename T>
bool stringToUnsigned(const std::string &s, T &out, const int base = 10) {
    char *end = nullptr;
    out = static_cast<T>(std::strtoul(s.c_str(), &end, base));
    if (end && *end != '\0') {
        return false;
    }

    return true;
}

/// Helper class that wraps a plain POSIX file descriptor.
/**
 * This wrapper takes care of closing the file descriptor upon destruction
 * time.
 **/
class FileDesc {
public:

    explicit FileDesc(int fd = -1) :
            m_fd{fd} {
    }

    FileDesc(FileDesc &&other) :
            FileDesc{} {
        // steal the rvalue's file descriptor so we take over ownership, while
        // the other doesn't close it during destruction. This allows to keep
        // this non-copyable type in containers.
        steal(other);
    }

    ~FileDesc() {
        if (valid()) {
            close();
        }
    }

    FileDesc(const FileDesc &other) = delete;
    FileDesc& operator=(const FileDesc &other) = delete;

    int get() const { return m_fd; }

    void set(int fd) {
        if (valid()) {
            close();
        }

        m_fd = fd;
    }

    void steal(FileDesc &other) {
        set(other.get());
        other.invalidate();
    }

    bool valid() const { return m_fd != -1; }
    bool invalid() const { return !valid(); }
    void invalidate() { m_fd = -1; }

    /// Explicitly close and invalidate() the currently stored file descriptor.
    void close();

protected:

    int m_fd = -1;
};

/// C++ wrapper around the POSIX struct stat.
class FileStatus :
        public ::stat {
public:

    FileStatus() :
            // zero initialize the `struct stat` using aggregate initialization of the base class
            ::stat{} {
    }

    FileStatus(const FileStatus &other) {
        *this = other;
    }

    FileStatus& operator=(const FileStatus &other) {
        *static_cast<struct stat*>(this) = other;
        return *this;
    }

    bool isLink() const { return S_ISLNK(this->st_mode); }
    bool isRegular() const { return S_ISREG(this->st_mode); }
    bool isDirectory() const { return S_ISDIR(this->st_mode); }

    /// Returns the file mode bits only.
    /**
     * This includes the permission bits any special bits like setXid but not
     * the file type bits
     **/
    auto getModeBits() const { return this->st_mode & ALLPERMS; }

    bool matchesOwnership(const uid_t uid, const gid_t gid) const {
        return this->st_uid == uid && this->st_gid == gid;
    }

    bool hasNonRootOwner() const {
        return this->st_uid != 0;
    }

    bool hasRootOwner() const {
        return !hasNonRootOwner();
    }

    bool hasNonRootGroup() const {
        return this->st_gid != 0;
    }

    bool hasRootGroup() const {
        return !hasNonRootGroup();
    }

    bool hasSafeOwner(const std::initializer_list<uid_t> &safe_uids) const {
        if (hasRootOwner())
           return true;

        for (const auto &uid: safe_uids) {
            if (matchesOwner(uid))
                return true;
        }

        return false;
    }

    bool hasSafeGroup(const std::initializer_list<gid_t> &safe_gids) const {
        if (!isGroupWritable() || hasRootGroup())
           return true;

        for (const auto &gid: safe_gids) {
            if (matchesGroup(gid))
                return true;
        }

        return false;
    }

    bool matchesOwner(uid_t user) const {
        return this->st_uid == user;
    }

    bool matchesGroup(gid_t group) const {
        return this->st_gid == group;
    }

    /// Checks whether both stat objects refer to the file object.
    /**
     * This compares device and inode identification to determine whether the
     * status refers to the same file system object.
     **/
    bool sameObject(const struct ::stat &other) const {
        return this->st_dev == other.st_dev && this->st_ino == other.st_ino;
    }

    bool isWorldWritable() const {
        return (this->st_mode & S_IWOTH) != 0;
    }

    bool isGroupWritable() const {
        return (this->st_mode & S_IWGRP) != 0;
    }

    bool fstat(const FileDesc &fd) {
        return ::fstat(fd.get(), this) == 0;
    }
};

/// A wrapper around the native `cap_t` type to ease memory management.
class FileCapabilities {
public:

    explicit FileCapabilities() {}

    ~FileCapabilities();

    FileCapabilities(FileCapabilities &&other) {
        // steal the rvalue's caps so we take over ownership, while
        // the other doesn't free them during destruction. This allows to keep
        // this non-copyable type in containers.
        m_caps = other.m_caps;
        other.invalidate();
    }

    FileCapabilities(const FileCapabilities &other) = delete;
    FileCapabilities& operator=(const FileCapabilities &other) = delete;

    bool operator==(const FileCapabilities &other) const;
    bool operator!=(const FileCapabilities &other) const {
        return !(*this == other);
    }

    // TODO: the code currently inconsistently uses `valid()` for testing for
    // emptiness in a lot of spots. But `valid()` can mean both: no
    // capabilities existing or an other error occurred. `errno` needs to be
    // inspected for this to correctly differentiate.
    // This class's API and the client code should be adjusted to make the
    // difference clear and the logic robust.
    bool valid() const { return m_caps != nullptr; }

    //! explicitly free and invalidate() the currently stored capabilities
    void destroy();

    cap_t raw() { return m_caps; }

    /// Set new capability data from a textual representation.
    /**
     *  If the operation fails then after return valid() will return `false`.
     **/
    void setFromText(const std::string &text);

    /// Set new capability data from the given file path.
    /**
     *  If the operation fails then after return valid() will return `false`.
     **/
    void setFromFile(const std::string &path);

    /// Applies the currently stored capability data to the given file descriptors.
    bool applyToFD(int fd) const;

    /// Returns a human readable string describing the current capability data.
    /**
     *  \return The human readable string on success, an empty string on error.
     **/
    std::string toText() const;

protected: // functions

    void invalidate() { m_caps = nullptr; }

protected: // data

     cap_t m_caps = nullptr;
};

#endif // inc. guard

// vim: et ts=4 sts=4 sw=4 :
