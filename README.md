# CSCI 4061 Fall 2023 Programming Assignment 4

Canvas PA Group 60

### Group Members:
- Matthew Breach (breac001) 
- Matthew Johnson (joh18723)
- Harrison Wallander (walla875)

### CSELabs Computer Used for Testing:
- csel-kh1260-14.cselabs.umn.edu

### Makefile Changes:
- None

### Additional Assumptions:
- Two notes:
    - Under `client.c`, we've added a parameter to the definition of `recieve_files()` to handle passing the `filesize` of the rotated image, as recieved from the server, into the funciton.
    - Under `server.h`, we've added `sys/stat.h` to the includes so that we can use the `stat` function within `server.c` to determine the length of the rotated image to send to the client.

### AI Code:
- None

### Individual Contributions Plan:
- breac001
    - client.c, some README, debugging, error handling, code linting
- joh18723
    - README, some client.c, debugging, error handling
- walla875
    - server.c, some README, debugging, error handling

### Pseudocode for Our Project:
1. client.c:
```
send_file(socket, fileName){
    open file(fileName)
    
    set up new packet
    memset packet
    send(size of file and rotation angle)

    send(file bytes until bytesSent == sizeof(file))
    close(file)
    
    return 0
}

receive_file(socket, fileName){
    set up recieving buffer
    open(fileName) (checking for error)

    set up new packet
    memset packet
    recv(socket) for img size

    call recv until file size is met

    close(file)
    return 0
}


main (argc, argv[]) {
    check for 4 arguments
    if not 4  
        return 1
    check for valid rotation angle input
    if not 180 or 270
        exit(1)
        
    set inputDir to argv[1]
    set outputDir to argv[2]
    create socket (checking for error)
    set port and addr
    connect to socket (checking for error)
    iterate through directory {
        check if file is not a directory
        if not directory {
            create imgPath variable from ent->d_name
            set requests[numRequests].file_name to imgPath
            set requests[numRequests].rotation_angle  to argv[3]
            increment numRequests
        }
    }
    close directory (checking for error)
    
    set up packet struct
    while numProcessed < numRequests{
        memset struct
        open requests[numProcessed].file_name (checking for error)

        set packet operation to IMG_OP_ROTATE
        set flag to corresponding img rotation angle
        send_packet(sockfd, packet)
        
        send_file(sockfd, currentImgFile) (checking for errors)

        close(file)

        set up recieving buffer
        recieve_packet(sockfd, packet) (error check)
        check if received packet includes ACK operation
        if (NAK){error and exit}
        recieve_file(sockfd, recievingBuffer) (error check)
        increment numProcessed
        free(packet)
    }

    memset packet
    set packet.operation to IMG_OP_EXIT to signal client termination

    send(packet) (checking for error)
    close(sockfd) (checking for error)
    return 0
}
```
2. In server.c:
```
clientHandler(socket){
    create RECVpacket struct
    create RETURNpacket struct
    while (1) {
        clear both packet structs
       
        recv(from socket, store in packet struct, sizeof packet) (error check)
        determine operation, flags, and size of image, store as ints
        
        if (operation == exit) {break}
        
        create image char* with malloc of sizeof(char)*image size
        recv(from socket, store in image char*, image size) (error check)
        
        write char* into an image file with correct name
        rotate the image file as required by inputs
        if (error rotating){
            set NAK operation in packet
            send(to socket, packet, sizeof packet, 0) (checking for error)
            close(connection)
            free packet structs
            pthread_exit
        }
        
        clear image char* with memset for reuse for sending
        
        set ACK operation in packet for return
        send(to socket, packet, sizeof packet, 0) (error check)
        
        read rotated image as bytes into the image char*
        process image
        rotate image
        send(to socket, image char*, image size, 0) (error check)
        
        free(char* used to store image)
        free img_matrix and result_matrix
        delete temp file
    }
    
    free packet structs
    pthread_exit
}

main(argc, argv[]){
    Create listen socket file descriptor (checking for error)
    create sockaddr_in struct
    memset sockaddr_in
    set sockaddr_in port number, family, addr
    bind address and port to socket for listening (checking for error)
    while(1) {
        listen on socket (checking for error)
        create clientddr sockaddr_in struct
        accept connections from client into conn_fd (checking for error)
        create client handling thread with clientHandler function and conn_fd socket arg
        join thread once done
    }
    close connection and listen sockets
    return 0
}
```
