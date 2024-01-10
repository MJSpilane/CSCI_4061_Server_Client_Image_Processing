#include "client.h"

#define PORT 2800
#define BUFFER_SIZE 1024 

request_t requests[MAX_QUEUE_LEN];
int numRequests = 0;
int rotAngle = 0;

int send_file(int socket, const char *filename) {
    // Open the file
    FILE *img = fopen(filename, "rb");
    if(img == NULL){
        perror("Error opening img to add to packet");
        return -1;
    }

    // Set up the request packet for the server and send it
    packet_t packet;
    memset(&packet, 0, sizeof(packet_t)); // set packet to 0's
    packet.operation = IMG_OP_ROTATE;

    if (rotAngle == 180)
        packet.flags = IMG_FLAG_ROTATE_180;
    else // This is safe since we verify rotation angle at top of main
        packet.flags = IMG_FLAG_ROTATE_270;

    // Determine file size
    if (fseek(img, 0, SEEK_END) != 0) {
        perror("feek error (client.c line 28)");
        return -1;
    }
    packet.size = htonl(ftell(img));
    rewind(img);

    if(packet.size == -1){ // Check if ftell returned an error
        perror("Error finding size of image");
        return -1;
    }

    // Send rotAngle and imageSize to server
    if(send(socket, &packet, sizeof(packet_t), 0) == -1){
        perror("Error sending through socket");
        return -1;
    }

    // Send the file data and check for errors
    int imgSize = ntohl(packet.size);
    char imgBuffer[BUFF_SIZE];
    imgBuffer[0] = '\0';
    size_t bytesRead = fread(imgBuffer, 1, BUFF_SIZE, img);
    size_t bytesSent = 0;
    if(bytesRead == -1){
        perror("Error reading img from file");
        return -1;
    }

    while(bytesRead > 0){
        bytesSent = send(socket, imgBuffer, bytesRead, 0);
        if(bytesSent == -1){
            perror("Error sending img data");
            return -1;
        }

        imgSize -= bytesSent;
        imgBuffer[0] = '\0';
        bytesRead = fread(imgBuffer, 1, BUFF_SIZE, img);
        if(bytesRead == -1){
            perror("Error reading img from file");
            return -1;
        }
    }

    // Ensure full image has been sent to server
    if(imgSize > 0){
        perror("Error sending full image");
        return -1;
    }

    if(fclose(img) == EOF){
        perror("fclose error");
        return -1;
    }
    return 0;
}

int receive_file(int socket, const char *filename, int filesize) {
    // Open the file
    FILE *img = fopen(filename, "wb");
    if(img == NULL){
        perror("Error opening output img");
        return -1;
    }

    // Receive response packet
    packet_t packet;
    memset(&packet, 0, sizeof(packet_t)); // set packet to 0's

    // Receive the file data and write to output file
    char imgBuffer[BUFF_SIZE];
    imgBuffer[0] = '\0';
    int bytesRead = recv(socket, imgBuffer, BUFF_SIZE, 0);
    size_t totBytes = 0;
    if(bytesRead == -1){
        perror("Error recieving img data from server");
        return -1;
    }

    while(bytesRead > 0){
        if(fwrite(imgBuffer, 1, bytesRead, img) == false) {
            perror("fwrite error");
            return -1;
        }
        totBytes += bytesRead;

        // Exit loop once entire file is recieved
        if(totBytes >= filesize){
            break;
        }

        imgBuffer[0] = '\0';
        bytesRead = recv(socket, imgBuffer, BUFF_SIZE, 0);
        if(bytesRead == -1){
            perror("Error recieving img data from server");
            return -1;
        }
    }

    if(fclose(img) == EOF){
        perror("fclose error");
        return -1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if(argc != 4){
        fprintf(stderr, "Usage: ./client File_Path_to_images File_Path_to_output_dir Rotation_angle. \n");
        return 1;
    }

    // Verify and handle inputs
    rotAngle = atoi(argv[3]);
    if ((rotAngle != 180) && (rotAngle != 270)){
        printf("Invalid rotation angle input\n");
        exit(1);
    }
    char *inputDir = argv[1];
    char *outputDir = argv[2];
    
    // Set up socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){
        perror("Error creating socket");
    }
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(PORT);

    // Connect the socket
    if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) == -1){
        perror("Error connecting to socket");
        exit(1);
    }

    // Read the directory for all the images to rotate
    struct dirent *ent;
    DIR *dir = opendir(inputDir);
    if (dir == NULL){
        perror("Error opening directory");
        exit(1);
    }

    while((ent = readdir(dir)) != NULL){
        // Add non-directory files to the request queue
        if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0){
            char imgPath[BUFF_SIZE];
            if(snprintf(imgPath, sizeof(imgPath), "%s", ent->d_name) < 0){
                perror("snprintf error");
                return -1;
            }
            requests[numRequests].file_name = malloc(strlen(imgPath) + 1);
            strcpy(requests[numRequests].file_name, imgPath);

            requests[numRequests].rotation_angle = rotAngle;
            
            numRequests++;
        }
    }

    if(closedir(dir) == -1){
        perror("closedir error");
        return -1;
    }
    
    // Process the images in the request queue
    int numProcessed = 0;
    while(numProcessed < numRequests){
        // Send requests[numProcessed] request to server
        char inputPath[BUFF_SIZE];
        memset(inputPath, 0, BUFF_SIZE);
        snprintf(inputPath, sizeof(inputPath), "%s/%s", inputDir, requests[numProcessed].file_name);
        if(send_file(sockfd, inputPath) == -1){
            perror("Error sending file");
            exit(1);
        }

        // Check that the request was acknowledged
        packet_t recvPacket;
        memset(&recvPacket, 0, sizeof(packet_t));
        int ret = recv(sockfd, &recvPacket, sizeof(packet_t), 0);
        if (ret == -1){
            perror("recv error");
            exit(1);
        }
        if(recvPacket.operation != IMG_OP_ACK){
            perror("Server ack error");
            exit(1);
        }

        // Receive the processed image and save it in the output dir
        char outputPath[BUFF_SIZE];
        memset(outputPath, 0, BUFF_SIZE);
        snprintf(outputPath, sizeof(outputPath), "%s/%s", outputDir, requests[numProcessed].file_name);
        if(receive_file(sockfd, outputPath, ntohl(recvPacket.size)) == -1){
		    perror("Error recieving file from server");
		    exit(1);
	    }

        numProcessed++;
    }

    // Terminate the connection once all images have been processed
    packet_t packet;
    memset(&packet, 0, sizeof(packet_t));
    packet.operation = IMG_OP_EXIT;
    if(send(sockfd, &packet, sizeof(packet_t), 0) == -1){
        printf("Error sending IMG_OP_EXIT to server\n");
        close(sockfd);
        exit(1);
    }

    if(close(sockfd) == -1){
        perror("error closing sockfd");
        return -1;
    }

    // Release any resources
    for(int i = 0; i < numRequests; i++){
        free(requests[i].file_name);
    }

    return 0;
}
