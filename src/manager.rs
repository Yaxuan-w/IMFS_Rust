#![allow(dead_code)]

use std::slice;
pub use std::sync::{LazyLock as RustLazyGlobal, Mutex as RustMutex};
use std::ptr::copy;
pub struct Memory {
    pub base_address: RustMutex<usize>,
    pub memory_list: RustMutex<Vec<usize>>,
    pub inode: usize,
}

// We want to Memory to be a global variable 
pub static GLOBAL_MEMORY: RustLazyGlobal<Memory> = RustLazyGlobal::new(|| {
    let page_size = 4096;
    // For test purpose
    let size = 1024 * 1024;
    
    let num_pages = if size % page_size == 0 {
        size / page_size
    } else {
        size / page_size + 1
    };

    Memory {
        base_address: RustMutex::new(0),
        memory_list: RustMutex::new(vec![0; num_pages]),
    }
});

pub fn allocate(request_size: usize) -> Vec<usize> {
    let memory_list_mutex = &GLOBAL_MEMORY.memory_list;
    let mut memorylist = memory_list_mutex.lock().unwrap();
    let page_size: usize = 4096; 
    // Compute number of pages we need
    let num_pages_needed = if request_size % page_size == 0 {
        request_size / page_size
    } else {
        request_size / page_size + 1
    };
    // Iterate memory list, allocate un-continous pages, and return index of new allocated page
    let mut allocated_block = Vec::new();
    for index in 0..memorylist.len() {
        if memorylist[index] == 0 {
            memorylist[index] = 1;
            allocated_block.push(index);
            if allocated_block.len() == num_pages_needed {
                return allocated_block;
            }
        }
    }
    // If there's no enough space for allocation, rollback assigned page tags
    if !allocated_block.is_empty() {
        for &index in &allocated_block {
            memorylist[index] = 0;
        }
    }
    panic!("No enough free pages available");
}

pub fn remove_fs(index_list: Vec<usize>) {
    let memory_list_mutex = &GLOBAL_MEMORY.memory_list;
    let mut memorylist = memory_list_mutex.lock().unwrap();
    for &index in &index_list {
        if index < memorylist.len() {
            memorylist[index] = 0;
        }
    }
}

pub struct EmulatedFile {
    pub filesize: usize,
    pub memory_block: Vec<usize>,
}

impl EmulatedFile {

    fn new() -> std::io::Result<EmulatedFile> {

        Ok(EmulatedFile {filesize: 0 as usize, memory_block: Vec::new()})

    }

    pub fn readat(&self, ptr: *mut u8, length: usize, offset: usize) -> std::io::Result<usize> {
        let mut ptr = ptr;
        let page_size = 4096;
        let _buf = unsafe {
            assert!(!ptr.is_null());
            slice::from_raw_parts_mut(ptr, length)
        };

        if offset > self.filesize {
            panic!("Seek offset extends past the EOF!");
        }
        // Calculate the offset
        // offset_block = start from which block
        // offset_pos = start from which position inside that block
        let (offset_block, offset_pos) = if offset / page_size == 0 {
            (0, offset)
        } else {
            (offset / page_size, offset % page_size)
        };
        let mut remain_len = length;
        for (i, &index) in self.memory_block.iter().enumerate() {
            if i < offset_block {
                // Skip blocks before starting
                continue;
            }
            let mem_base_addr_lock = &GLOBAL_MEMORY.base_address;
            match mem_base_addr_lock.lock() {
                Ok(mem_base_addr) => {
                    // Set ptr according to the start address for this block
                    let block_start = *mem_base_addr + page_size * index;
                    // Only consider offset in the first readable block
                    let ptr_mem: *mut u8 = (block_start + if i == offset_block { offset_pos } else { 0 }) as *mut u8;
                    // Calculate how many bytes need to be read this time
                    let bytes_to_copy = remain_len.min(page_size - if i == offset_block { offset_pos } else { 0 });
                    // Update remaining length
                    remain_len -= bytes_to_copy;
                    
                    unsafe {
                        copy(ptr_mem, ptr, bytes_to_copy);
                        ptr = ptr.add(bytes_to_copy);
                    }

                    if remain_len == 0 {
                        break;
                    }
                }
                Err(e) => {
                    panic!("Failed to acquire the lock in readat: {:?}", e);
                }
            }
        }
        
        Ok(length - remain_len)

    }

    // Write to file from provided C-buffer
    pub fn writeat(&mut self, ptr: *const u8, length: usize, offset: usize) -> std::io::Result<usize> {
        let mut ptr = ptr;
        let page_size = 4096;
        let _buf = unsafe {
            assert!(!ptr.is_null());
            slice::from_raw_parts(ptr, length)
        };

        if offset > self.filesize {
            panic!("Seek offset extends past the EOF!");
        }

        if self.memory_block.len() == 0 {
            // Initialization file memory
            self.filesize = length;
            let allocated = allocate(length);
            self.memory_block.extend(allocated.iter().cloned());
        } else if length + offset > self.filesize {
            let extendsize = length + offset - self.filesize;
            // If need extend
            self.filesize = length + offset;
            let extendblock = allocate(extendsize);
            self.memory_block.extend(extendblock.iter().cloned());
        }
        // Calculate the offset
        // offset_block = start from which block
        // offset_pos = start from which position inside that block
        let (offset_block, offset_pos) = if offset / page_size == 0 {
            (0, offset)
        } else {
            (offset / page_size, offset % page_size)
        };
        let mut remain_len = length;
        for (i, &index) in self.memory_block.iter().enumerate() {
            if i < offset_block {
                // Skip blocks before starting
                continue;
            }
            // Set ptr according to the start address for this block
            let mem_base_addr_lock = &GLOBAL_MEMORY.base_address;
            match mem_base_addr_lock.lock() {
                Ok(mem_base_addr) => {
                    let block_start = *mem_base_addr + page_size * index;
                    // Only consider offset in the first readable block
                    let ptr_mem: *mut u8 = (block_start + if i == offset_block { offset_pos } else { 0 }) as *mut u8;
                    // Calculate how many bytes need to be read this time
                    let bytes_to_copy = remain_len.min(page_size - if i == offset_block { offset_pos } else { 0 });
                    // Update remaining length
                    remain_len -= bytes_to_copy;
                    
                    unsafe {
                        copy(ptr, ptr_mem, bytes_to_copy);
                        ptr = ptr.add(bytes_to_copy);
                    }

                    if remain_len == 0 { break; }
                },
                Err(e) => {
                    panic!("Failed to acquire the lock in writeat: {:?}", e);
                }
            }
            
        }
        
        Ok(length - remain_len)

    }

    pub fn shrink(&mut self, length: usize) -> std::io::Result<()> {
        let page_size = 4096;
        if length > self.filesize { 
            panic!("Something is wrong. File is already smaller than length.");
        }
        // Find unused block: get the block and pos
        let new_block_total = if length / page_size == 0 {
            0
        } else {
            length / page_size + 1
        };
        let mut removed_block = Vec::new();
        // Update memory block
        if new_block_total + 1 < self.memory_block.len() {
            // Get the deleted block
            removed_block = self.memory_block.iter().skip(new_block_total + 1).cloned().collect();
            self.memory_block.truncate(new_block_total + 1);
        }
        // Update memory list
        remove_fs(removed_block);
        // Update filesize
        self.filesize = length;         
        Ok(())
    }

    pub fn readfile_to_new_bytes(&self) -> std::io::Result<Vec<u8>> {
        // let mut stringbuf = Vec::new();
        let mut stringbuf = vec![0; self.filesize];
        self.readat(stringbuf.as_mut_ptr(), self.filesize, 0)?;
        Ok(stringbuf)
    }

    pub fn writefile_from_bytes(&mut self, buf: &[u8]) -> std::io::Result<()> {

        let length = buf.len();
        let offset = self.filesize;

        let ptr: *const u8 = buf.as_ptr();
    
        let _ = self.writeat(ptr, length, offset);

        if offset + length > self.filesize {
            self.filesize = offset + length;
        }
        
        Ok(())
    }

    pub fn zerofill_at(&mut self, offset: usize, count: usize) -> std::io::Result<usize> {
        let buf = vec![0; count];
        if offset > self.filesize {
            panic!("Seek offset extends past the EOF!");
        }
        let bytes_written = self.writeat(buf.as_ptr(), buf.len(), offset)?;

        if offset + count > self.filesize {
            self.filesize = offset + count;
        }

        Ok(bytes_written)
    }
 
}

pub fn allocate_memory(size: usize) -> Vec<u8> {
    let buffer = vec![0u8; size];
    buffer
}

pub fn test() -> std::io::Result<()> {
    println!("\nTEST RESULT\n");
    // Initialize a file
    let mut emulated_file = EmulatedFile::new()?;
    const MB: usize = 1024 * 1024;
    let mut vec = Vec::with_capacity(MB);
    unsafe {
        vec.set_len(MB);
    }
    let ptr:*mut u8 = vec.as_mut_ptr();
    std::mem::forget(vec);
    
    let start_address = ptr as usize;
    if let Ok(mut addr) = GLOBAL_MEMORY.base_address.lock() {
        *addr = start_address;
    }

    allocate_memory(5 * MB);
    println!("[*] File size after initialization: {}", emulated_file.filesize);
    println!("[*] Memory block start address: {:?}", start_address);
    println!("----------------------------- Write 01 02 03 04 05 into File -----------------------------");
    // Data to write
    let data_to_write: Vec<u8> = vec![1, 2, 3, 4, 5];
    let write_offset = 0;
    println!("[-] offset: {}", write_offset);
    // Write data to the file
    let bytes_written = emulated_file.writeat(data_to_write.as_ptr(), data_to_write.len(), write_offset)?;
    println!("[*] bytes_written: {}", bytes_written);
    println!("[*] File size after 1st write:{}", emulated_file.filesize);
    
    println!("----------------------------- Read 01 02 03 04 05 from File -----------------------------");
    // Buffer to read data into
    let mut read_buffer: Vec<u8> = vec![0; 5];
    let read_offset = 0;
    println!("[-] offset: {}", read_offset);
    // Read data from the file
    let bytes_read = emulated_file.readat(read_buffer.as_mut_ptr(), read_buffer.len(), read_offset)?;
    println!("[*] bytes_read: {}", bytes_read);
    println!("[-] Expected Result: {:?}", data_to_write);
    println!("[*] Actual Result: {:?}", read_buffer);

    println!("----------------------------- Write 01 02 03 04 05 into File at the end -----------------------------");
    println!("[-] offset: {}", 5);
    let bytes_written_2 = emulated_file.writeat(data_to_write.as_ptr(), data_to_write.len(), 5)?;
    println!("[*] bytes_written_2: {}", bytes_written_2);
    println!("[*] File size after 2nd write:{}", emulated_file.filesize);

    println!("----------------------------- Read 04 05 from the file -----------------------------");
    let mut read_buffer_2: Vec<u8> = vec![0; 2];
    println!("[-] offset: {}", 3);
    let bytes_read_2 = emulated_file.readat(read_buffer_2.as_mut_ptr(), 2, 3)?;
    println!("[*] bytes_read_2: {}", bytes_read_2);
    println!("[*] Read result: {:?}", read_buffer_2);

    println!("----------------------------- Remove last 3 in file -----------------------------");
    match emulated_file.shrink(7) {
        Ok(()) => println!("[*] Success!"),
        Err(e) => println!("[!] Failed {}", e),
    }

    println!("----------------------------- Read entire file -----------------------------");
    println!("[-] Expected output: {:?}", vec![1, 2, 3, 4, 5, 1, 2]);
    let mut read_shrink: Vec<u8> = vec![0; emulated_file.filesize];
    let bytes_read_shrink = emulated_file.readat(read_shrink.as_mut_ptr(), read_shrink.len(), 0)?;
    println!("[*] bytes_read: {}", bytes_read_shrink);
    println!("[*] Read Result: {:?}", read_shrink);
    println!("[*] File size after shrink: {}", emulated_file.filesize);

    println!("----------------------------- Write 9 10 11 into file -----------------------------");
    let alph_to_write: Vec<u8> = vec![9, 10, 11];
    let bytes_to_write_3 = emulated_file.writeat(alph_to_write.as_ptr(), alph_to_write.len(), 5)?;
    println!("[-] offset: {}", 5);
    println!("[*] bytes_written: {}", bytes_to_write_3);

    println!("----------------------------- Read entire file -----------------------------");
    let mut read_after_overwrite = vec![0; emulated_file.filesize];
    let bytes_read = emulated_file.readat(read_after_overwrite.as_mut_ptr(), read_after_overwrite.len(), 0)?;
    println!("[-] Expected output: {:?}", vec![1, 2, 3, 4, 5, 9, 10, 11]);
    println!("[*] bytes_read: {}", bytes_read);
    println!("[*] Read Result: {:?}", read_after_overwrite);
    println!("[*] File size after shrink: {}", emulated_file.filesize);

    println!("----------------------------- writefile_from_bytes -----------------------------");
    let _ = emulated_file.writefile_from_bytes(&data_to_write)?;
    println!("[-] Expected file size: {}", 13);
    println!("[*] Actual file size: {}", emulated_file.filesize);

    println!("----------------------------- readfile_to_new_bytes -----------------------------");
    let readfile_result = emulated_file.readfile_to_new_bytes()?;
    println!("[-] Expected output: {:?}", vec![1, 2, 3, 4, 5, 9, 10, 11, 1, 2, 3, 4, 5]);
    println!("[*] readfile_to_new_bytes Result: {:?}", readfile_result);

    println!("----------------------------- zerofill_at (fill last 3 to 0) -----------------------------");
    let _ = emulated_file.zerofill_at(10, 4);
    let read_result = emulated_file.readfile_to_new_bytes()?;
    println!("[-] Expected output: {:?}", vec![1, 2, 3, 4, 5, 9, 10, 11, 1, 2, 0, 0, 0, 0]);
    println!("[*] zerofill_at result: {:?}", read_result);
    println!("[*] File size should be changed to 14, actual: {}", emulated_file.filesize);

    
    unsafe { let _buffer = Vec::from_raw_parts(ptr, MB, MB); }
    Ok(())
}
