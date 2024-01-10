#include "server.h"

#define PORT 2800
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024 


void *clientHandler(void *socket) {
    int ret;
    int *inputNum = (int*) socket;
    int conn_fd = *inputNum;

    // Set up packets
    struct packet *recvpacket = malloc(sizeof(packet_t));
    struct packet *returnpacket = malloc(sizeof(packet_t));
    recvpacket->operation = IMG_OP_ACK;

    // Receive packets from the client
    while (recvpacket->operation != IMG_OP_EXIT){
        memset(recvpacket, 0, sizeof(packet_t));
        memset(returnpacket, 0, sizeof(packet_t));

        // Receive packets from the client
        ret = recv(conn_fd, recvpacket, sizeof(packet_t), 0);
        if(ret == -1){
            perror("recv error");
            exit(1);
        }

        // Determine the packet operatation and flags
        if (recvpacket->operation == IMG_OP_EXIT){
            close(conn_fd);
            free(recvpacket);
            free(returnpacket);
            pthread_exit(NULL);
        }
        if (recvpacket->operation != IMG_OP_ROTATE){
            returnpacket->operation = IMG_OP_NAK;
            ret = send(conn_fd, returnpacket, sizeof(packet_t), 0);
            if (ret == -1){
                perror("send error");
                exit(1);
            }
            break;
        }

        // Set up and send ACK packet
        returnpacket->operation = IMG_OP_ACK;
        ret = send(conn_fd, returnpacket, sizeof(packet_t), 0);
        if (ret == -1){
            perror("send error");
            exit(1);
        }

        // Receive the image data using the size
        unsigned char *imgFile = malloc(sizeof(char)*ntohl(recvpacket->size));
        ret = recv(conn_fd, imgFile, sizeof(char)*ntohl(recvpacket->size), 0);
        if(ret == -1){
            perror("recv error");
            exit(1);
        }

        // Set up image rotation code
        int width, height, comp;
        uint8_t *linImage = stbi_load_from_memory(imgFile, ntohl(recvpacket->size), &width, &height, &comp, 1);

        // Set up result and image matrices
        uint8_t **result_matrix = (uint8_t **)malloc(sizeof(uint8_t*) * width);
        uint8_t** img_matrix = (uint8_t **)malloc(sizeof(uint8_t*) * width);
        for(int i = 0; i < width; i++){
            result_matrix[i] = (uint8_t *)malloc(sizeof(uint8_t) * height);
            img_matrix[i] = (uint8_t *)malloc(sizeof(uint8_t) * height);
        }

        // Convert linear to 2D for image rotation
        linear_to_image(linImage, img_matrix, width, height);

        // Determine rotation based on packet flag
        if(recvpacket->flags == IMG_FLAG_ROTATE_180){ // Rotate 180 degrees, flip left-to-right
            flip_left_to_right(img_matrix, result_matrix, width, height);
        }
        else if(recvpacket->flags == IMG_FLAG_ROTATE_270){ // Rotate 270 degrees, flip upside down
            flip_upside_down(img_matrix, result_matrix, width, height);
        }
        else{
            perror("invalid image operation in flags");
            exit(1);
        }

        uint8_t *img_array = (uint8_t*)malloc(sizeof(uint8_t) * width * height);

        // Flatten matrix
        flatten_mat(result_matrix, img_array, width, height);

        // Build temporary file to store image to send to client
        char tempFile[12] = "tempXXXXXX";
        int tmp_fd = mkstemp(tempFile);
        lseek(tmp_fd, 0, SEEK_SET);

        // Write image to temp file
        stbi_write_png(tempFile, width, height, CHANNEL_NUM, img_array, width * CHANNEL_NUM);
        lseek(tmp_fd, 0, SEEK_SET);
        
        // Get file length for read and send
        struct stat st;
        stat(tempFile, &st);
        int fileLen = st.st_size;
        
        // Read temp file into imgBuffer
        char imgBuffer[fileLen];
        memset(imgBuffer, 0, SEEK_SET);
        read(tmp_fd, imgBuffer, fileLen);

        // Send image to client
        ret = send(conn_fd, imgBuffer, fileLen, 0);
        if (ret == -1){
            perror("send error");
            exit(1);
        }

        // Free dynamically-allocated memory within loop
        for(int i = 0; i < width; i++){
            free(img_matrix[i]);
            free(result_matrix[i]);
        }
        free(img_matrix);
        free(result_matrix);
        free(img_array);

        // Reset img_matrix and result_matrix
        img_matrix = NULL;
        result_matrix = NULL;

        // Close and unlink temporary file
        close(tmp_fd);
        unlink(tempFile);
    }

    // Free dymanically-allocated memory outside of loop
    free(recvpacket);
    free(returnpacket);

    // Exit client handler thread
    pthread_exit(NULL);
}

int main(int argc, char* argv[]) {
    // Creating socket file descriptor
    int listen_fd, conn_fd;

    // Set up socket to listen on
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_fd == -1){
        perror("socket error");
        exit(1);
    }

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // Listen to any of the network interface (INADDR_ANY)
    servaddr.sin_port = htons(PORT); // Port number

    // Bind the socket to the port
    int ret = bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    if(ret == -1){
        perror("bind error");
        exit(1);
    }

    while(1){
        // Listen on the socket
        ret = listen(listen_fd, MAX_CLIENTS);
        if(ret == -1){
            perror("listen error");
            exit(1);
        }

        // Accept connections and create the client handling threads
        struct sockaddr_in clientaddr;
        socklen_t clientaddr_len = sizeof(clientaddr);
        conn_fd = accept(listen_fd, (struct sockaddr *) &clientaddr, &clientaddr_len);
        if(conn_fd == -1){
            perror("accept error");
            exit(1);
        }

        pthread_t procThread;
        pthread_create(&procThread, NULL, (void*) clientHandler, (void*) &conn_fd);
        pthread_join(procThread, NULL);
    }

    // Close sockets
    if(close(conn_fd) == -1){
        perror("Error closing conn_fd");
        return -1;
    }
    
    if(close(listen_fd) == -1){
        perror("Error closing listen_fd");
        return -1;
    }

    return 0;
}
