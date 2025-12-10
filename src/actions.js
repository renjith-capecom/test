// Server Actions module - this will be registered in the module manifest
// These are the functions that can be called from the client

export async function greetUser(name) {
  return `Hello, ${name}!`;
}

export async function processData(data) {
  return { processed: true, data };
}
