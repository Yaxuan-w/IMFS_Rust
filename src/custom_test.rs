// use crate::manager;
// pub fn tests() {
//     let base_address = 0;
//     let memory_size = 1 * 1024 * 1024 * 1024; // 1GB
//     let (mut free_list, mut used_list) = manager::init_memory_allocation(base_address, memory_size);
//     println!("Free list:");
//     for block in free_list.iter() {
//         println!("Address: {}, Size: {}", block.start_address, block.size);
//     }

//     println!("\nUsed list:");
//     for block in used_list.iter() {
//         println!("Address: {}, Size: {}", block.start_address, block.size);
//     }

//     println!("\n------------------------------------------------");

//     let request_sizes = vec![128 * 1024 * 1024, 400 * 1024 * 1024, 200 * 1024 * 1024]; // Request 128MB, 400MB, 200MB

//     for size in request_sizes {
//         let address = manager::allocate_memory(size, &mut free_list, &mut used_list);
//         println!("\nAllocated {} bytes at address {}", size, address);
//     }

//     println!("\n------------------------------------------------");
//     println!("\nFree list:");
//     for block in free_list.iter() {
//         println!("Address: {}, Size: {}", block.start_address, block.size);
//     }

//     println!("\nUsed list:");
//     for block in used_list.iter() {
//         println!("Address: {}, Size: {}", block.start_address, block.size);
//     }
// }
