//! 平台特定模块 - 处理不同操作系统的特定功能

#[cfg(unix)]
mod unix {
    use libc::{rlimit, setrlimit, setsid, RLIMIT_NOFILE};
    use std::net::TcpListener;

    /// 设置最大文件描述符数量
    pub fn set_max_nofile() {
        let limit = rlimit {
            rlim_cur: 1048576,
            rlim_max: 1048576,
        };

        unsafe {
            if setrlimit(RLIMIT_NOFILE, &limit) != 0 {
                log::error!("Failed to set RLIMIT_NOFILE");
            }
        }
    }

    /// 创建新会话
    pub fn create_new_session() {
        unsafe {
            setsid();
        }
    }

    /// 启用 TCP Fast Open
    pub fn enable_tcp_fastopen(listener: &TcpListener) -> Result<(), std::io::Error> {
        use std::os::unix::io::AsRawFd;

        const TCP_FASTOPEN: libc::c_int = 23;

        let fd = listener.as_raw_fd();
        let optval: libc::c_int = 1;

        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                TCP_FASTOPEN,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            )
        };

        if result != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::net::TcpListener;

    /// 设置最大文件描述符数量（Windows 上为空操作）
    pub fn set_max_nofile() {
        // Windows 没有类似的限制
    }

    /// 创建新会话（Windows 上为空操作）
    pub fn create_new_session() {
        // Windows 没有 setsid
    }

    /// 启用 TCP Fast Open
    #[allow(unused_variables)]
    pub fn enable_tcp_fastopen(listener: &TcpListener) -> Result<(), std::io::Error> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            setsockopt, IPPROTO_TCP, SOCKET,
        };

        const TCP_FASTOPEN: i32 = 15;

        let socket = listener.as_raw_socket() as SOCKET;
        let optval: i32 = 1;

        let result = unsafe {
            setsockopt(
                socket,
                IPPROTO_TCP as i32,
                TCP_FASTOPEN,
                &optval as *const _ as *const u8,
                std::mem::size_of_val(&optval) as i32,
            )
        };

        if result != 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

// 导出平台特定函数
#[cfg(unix)]
pub use unix::*;

#[cfg(windows)]
pub use windows::*;

/// 初始化平台特定设置
pub fn init_platform() {
    set_max_nofile();
    create_new_session();
}
