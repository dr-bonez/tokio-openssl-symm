use std::io::{Error as IoError, ErrorKind as IoErrorKind, Result as IoResult};
use std::pin::Pin;
use std::task::Context;
use std::task::Poll;

use openssl::{
    error::ErrorStack,
    symm::{Cipher, Crypter, Mode},
};
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;

pub struct EncryptWriter<W> {
    cipher: Cipher,
    writer: W,
    crypter: Crypter,
    written: usize,
    buf: Vec<u8>,
    is_finalized: bool,
}
impl<W> EncryptWriter<W> {
    pub fn new(
        writer: W,
        cipher: Cipher,
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Self, ErrorStack> {
        Ok(EncryptWriter {
            cipher,
            writer,
            crypter: Crypter::new(cipher, Mode::Encrypt, key, iv)?,
            written: 0,
            buf: Vec::new(),
            is_finalized: false,
        })
    }
}

impl<W> EncryptWriter<W>
where
    W: AsyncWrite,
{
    // self must be pinned
    unsafe fn poll_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        while self.written < self.buf.len() {
            match Pin::new_unchecked(&mut self.writer).poll_write(cx, &self.buf[self.written..]) {
                Poll::Ready(Ok(n)) => {
                    self.written += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.written = 0;
        self.buf.clear();
        Poll::Ready(Ok(()))
    }
}

impl<W> AsyncWrite for EncryptWriter<W>
where
    W: AsyncWrite,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<IoResult<usize>> {
        unsafe {
            let inner = self.get_unchecked_mut();
            match inner.poll_write_buf(cx) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            inner.buf.resize(buf.len() + inner.cipher.block_size(), 0);
            let len = match inner.crypter.update(buf, &mut inner.buf) {
                Ok(a) => a,
                Err(e) => return Poll::Ready(Err(IoError::new(IoErrorKind::Other, e))),
            };
            inner.buf.truncate(len);
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        unsafe {
            let inner = self.get_unchecked_mut();
            match inner.poll_write_buf(cx) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            Pin::new_unchecked(&mut inner.writer).poll_flush(cx)
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<IoResult<()>> {
        unsafe {
            let inner = self.get_unchecked_mut();
            if !inner.is_finalized {
                let init_len = inner.buf.len();
                inner.buf.resize(init_len + inner.cipher.block_size(), 0);
                let finalize_count = match inner.crypter.finalize(&mut inner.buf[init_len..]) {
                    Ok(a) => a,
                    Err(e) => return Poll::Ready(Err(IoError::new(IoErrorKind::Other, e))),
                };
                inner.buf.truncate(init_len + finalize_count);
                inner.is_finalized = true;
            }
            match inner.poll_write_buf(cx) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
            Pin::new_unchecked(&mut inner.writer).poll_shutdown(cx)
        }
    }
}

pub struct DecryptReader<R> {
    cipher: Cipher,
    reader: R,
    crypter: Crypter,
    read: usize,
    buf: Vec<u8>,
}
impl<R> DecryptReader<R> {
    pub fn new(
        reader: R,
        cipher: Cipher,
        key: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Self, ErrorStack> {
        Ok(DecryptReader {
            cipher,
            reader,
            crypter: Crypter::new(cipher, Mode::Decrypt, key, iv)?,
            read: 0,
            buf: Vec::new(),
        })
    }
}

impl<R> AsyncRead for DecryptReader<R>
where
    R: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<IoResult<usize>> {
        unsafe {
            let inner = self.get_unchecked_mut();

            let mut available = inner.buf.len() - inner.read;
            if available == 0 {
                inner.read = 0;
                inner.buf.clear();
                available = match Pin::new_unchecked(&mut inner.reader).poll_read(cx, buf) {
                    Poll::Ready(Ok(0)) => {
                        inner.buf.resize(inner.cipher.block_size(), 0);
                        match inner.crypter.finalize(&mut inner.buf) {
                            Ok(a) => a,
                            Err(e) => return Poll::Ready(Err(IoError::new(IoErrorKind::Other, e))),
                        }
                    }
                    Poll::Ready(Ok(n)) => {
                        inner.buf.resize(n + inner.cipher.block_size(), 0);
                        match inner.crypter.update(&buf[..n], &mut inner.buf) {
                            Ok(a) => a,
                            Err(e) => return Poll::Ready(Err(IoError::new(IoErrorKind::Other, e))),
                        }
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                };
                inner.buf.truncate(available);
            }
            let src_buf = if buf.len() >= available {
                &inner.buf[inner.read..]
            } else {
                &inner.buf[inner.read..(inner.read + buf.len())]
            };
            buf[..src_buf.len()].clone_from_slice(src_buf);
            inner.read += src_buf.len();

            Poll::Ready(Ok(src_buf.len()))
        }
    }
}
