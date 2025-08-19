# Initial 

Write simple client and server in golang to access bash over websocket, 
- write single binary for both client and server 
- include simple token based authentication passed as header or query param 
- all communication should be over websockets and ssl if enabled
- client should have options to skip ssl validation / insecure
- implement proper logging and production ready code
- server starts and start to listen on port from PORT env, response to any endpoint with 404 and /ws should be reserved for client to connect 
- client connects and is presented with full bash terminal
- multiple clients can be connected to same server, each having its own shell , client is presented with full tty over bash just as bash is accessed over terminal. CTRL+C on client terminates client connection 
- write single integration test case to test end to end , validate client and server works
