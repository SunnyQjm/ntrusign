//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_BUFFER_H
#define NTRUSIGN_BUFFER_H

#include <vector>
#include <cstdint>
#include <memory>

/**
 * @brief General-purpose automatically managed/resized buffer
 *
 * In most respect, the Buffer class is equivalent to a `std::vector<uint8_t>`, and it in fact
 * uses the latter as a base class. In addition to that, it provides the get<T>() helper method
 * that automatically casts the returned pointer to the requested type.
 */
class Buffer : public std::vector<uint8_t>
{
public:
  /** @brief Creates an empty Buffer
   */
  Buffer() = default;

  /** @brief Copy constructor
   */
  Buffer(const Buffer&);

  /** @brief Copy assignment operator
   */
  Buffer&
  operator=(const Buffer&);

  /** @brief Move constructor
   */
  Buffer(Buffer&&) noexcept;

  /** @brief Move assignment operator
   */
  Buffer&
  operator=(Buffer&&) noexcept;

  /** @brief Creates a Buffer with pre-allocated size
   *  @param size size of the Buffer to be allocated
   */
  explicit
  Buffer(size_t size)
      : std::vector<uint8_t>(size, 0)
  {
  }

  /** @brief Creates a Buffer by copying contents from a raw buffer
   *  @param buf const pointer to buffer to copy
   *  @param length length of the buffer to copy
   */
  Buffer(const void* buf, size_t length)
      : std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(buf),
                             reinterpret_cast<const uint8_t*>(buf) + length)
  {
  }

  /** @brief Creates a Buffer by copying the elements of the range [first, last)
   *  @param first an input iterator to the first element to copy
   *  @param last an input iterator to the element immediately following the last element to copy
   */
  template<class InputIt>
  Buffer(InputIt first, InputIt last)
      : std::vector<uint8_t>(first, last)
  {
  }

  /** @return pointer to the first byte of the buffer, cast to the requested type T
   */
  template<class T>
  T*
  get() noexcept
  {
    return reinterpret_cast<T*>(data());
  }

  /** @return const pointer to the first byte of the buffer, cast to the requested type T
   */
  template<class T>
  const T*
  get() const noexcept
  {
    return reinterpret_cast<const T*>(data());
  }
};

inline
Buffer::Buffer(const Buffer&) = default;

inline Buffer&
Buffer::operator=(const Buffer&) = default;

inline
Buffer::Buffer(Buffer&&) noexcept = default;

inline Buffer&
Buffer::operator=(Buffer&&) noexcept = default;

using BufferPtr = std::shared_ptr<Buffer>;
using ConstBufferPtr = std::shared_ptr<const Buffer>;

#endif //NTRUSIGN_BUFFER_H
