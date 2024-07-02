#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>

#define SERIAL_PORT "/dev/ttyS0"
#define BAUDRATE B9600 // Baud rate
#define MODEM_RESPONSE_BUFFER_SIZE 500

typedef struct definityline {
    // This struct defines necessary Definity line attributes.
    char port[8];
    char type[8];
    char name[29];
    char room[11];
    char result[10]; // Status for line ops (busy/release)
    char errcode[6]; // Hopefully this'll never actually need to be populated
    char attributes; // Bit 1 is going to be off-premises station, but no other details will be necessary.
} DEFLINE;

DEFLINE lineinfo = {{0}};

// A couple of functions are going to have to share, so we're going to have a few more global variables.

int modem_signals;
struct termios serial_settings;
char buffer[MODEM_RESPONSE_BUFFER_SIZE];
char sourcenum[8];
char destnum[8];
char dialstring[27];
char altstring[27];

FILE *logfile;
FILE *errorfile;
char timestring[30]; // For logger. This kinda sucks, but you really cna't return local char arrays.
int fd;
char codetype[40];
int ossifield[255]; // This is lazy; we really should be mallocing this. Maybe next time.

// Grumble grumble bloody Avaya grumble, make me
// write my own tokenizer...

// Seriously, who makes a 'machine friendly' format
// that you can't just strtok? This is just stupid.

// I solemly swear I didn't have ChatGPT write the tokenizer.
char* ossi_tokenizer(char *str, char **last_delim) {
    static char *last_str = NULL; // Static variable to keep track of last position
    char *token_start;

    // On initial call with a new string, update last_str
    if (str != NULL)
        last_str = str;

    // Skip over any leading delimiters
    /*
    while (last_str && (*last_str == '\n' || *last_str == '\t'))
        last_str++;
    */
    // If last_str is NULL or points to the end of the string, return NULL
    if (last_str == NULL || *last_str == '\0')
        return NULL;

    // Check which delimiter (newline or tab) we encounter first
    char *newline_pos = strchr(last_str, '\n');
    char *tab_pos = strchr(last_str, '\t');

    // Determine the position of the next delimiter
    char *next_delim;
    if (newline_pos != NULL && tab_pos != NULL) {
        if (newline_pos < tab_pos) {
            next_delim = newline_pos;
            *last_delim = "\n";
        } else {
            next_delim = tab_pos;
            *last_delim = "\t";
        }
    } else if (newline_pos != NULL) {
        next_delim = newline_pos;
        *last_delim = "\n";
    } else if (tab_pos != NULL) {
        next_delim = tab_pos;
        *last_delim = "\t";
    } else {
        next_delim = NULL;
    }

    // If no delimiter is found, the token extends to the end of the string
    if (next_delim != NULL) {
        *next_delim = '\0'; // Null terminate the token
        token_start = last_str;
        last_str = next_delim + 1; // Move last_str past the delimiter
    } else {
        token_start = last_str;
        last_str = NULL; // End of tokens
    }

    return token_start;
}

// This is an implementation of the Windows fsize() library function, since that doesn't exist on *nix systems.
long fsize(FILE *fp) {
    // ftell will return -1 if there's an error. This should be worked into all error handling functionality.
    fseek(fp, 0, SEEK_END);
    long bytes = ftell(fp);
    rewind(fp);
    return bytes;
}

const char *timeoutput() {
    time_t rawtime;
    struct tm *info;
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(timestring, 30, "%x - %I:%M %p", info);
    return timestring;
}

void disconnect_modem() {

    if (ioctl(fd, TIOCMGET, &modem_signals) == -1) {
        fprintf(logfile, "TIOCMGET in disconnect_modem failed!\n");
    }
    modem_signals &= ~TIOCM_DTR;
    //modem_signals &= ~TIOCM_RTS; // Unnecessary
    if (ioctl(fd, TIOCMSET, &modem_signals) == -1) {
        fprintf(logfile, "disconnect_modem() failed!\n");
    }
    return;
}

char * code_identify(int code, char * token) {
    switch(code) {
        case 0x8005ff00:
            sprintf(codetype, "Extension");
            break;
        case 0x004fff00:
            sprintf(codetype, "Type");
            strncpy(lineinfo.type, token, 7);
            break;
        case 0x8004ff00:
            sprintf(codetype, "Logical Port");
            strncpy(lineinfo.port, token, 7);
            break;
        case 0x8003ff00:
            sprintf(codetype, "Name");
            strncpy(lineinfo.name, token, 27);
            break;
        case 0x0015ff00:
            sprintf(codetype, "Lock Messages?");
            break;
        case 0x0016ff00:
            sprintf(codetype, "Security Code");
            break;
        case 0x8007ff00:
            sprintf(codetype, "Coverage Path 1");
            break;
        case 0xce2aff00:
            sprintf(codetype, "Coverage Path 2");
            break;
        case 0x4e22ff00:
            sprintf(codetype, "Hunt-to Station");
            break;
        case 0x4a3bff00:
            sprintf(codetype, "TN");
            break;
        case 0x8001ff00:
            sprintf(codetype, "COR");
            break;
        case 0x8002ff00:
            sprintf(codetype, "COS");
            break;
        case 0x002dff00:
            sprintf(codetype, "Tests?");
            break;
        case 0xe613ff00:
            sprintf(codetype, "Loss Group");
            break;
        case 0x0011ff00:
            sprintf(codetype, "Off Premises Station?");
            if (token != NULL) {
                if (token[0] == 'y') lineinfo.attributes |= 1;
                else if (token[0] =='n') lineinfo.attributes &= ~1;
            }
            break;
        case 0x002cff00:
            sprintf(codetype, "Message Waiting Indicator");
            break;
        case 0x4a42ff00:
            sprintf(codetype, "Message Lamp Ext");
            break;
        case 0x0013ff00:
            sprintf(codetype, "LWC Reception");
            break;
        case 0x0023ff00:
            sprintf(codetype, "LWC Activation?");
            break;
        case 0x6605ff00:
            sprintf(codetype, "LWC Log External Calls?");
            break;
        case 0x07d1ff00:
            sprintf(codetype, "CDR Privacy?");
            break;
        case 0x0024ff00:
            sprintf(codetype, "Redirect Notification?");
            break;
        case 0x4a40ff00:
            sprintf(codetype, "Per Button Ring Control?");
            break;
        case 0x002bff00:
            sprintf(codetype, "Bridge Call Alerting?");
            break;
        case 0x0047ff00:
            sprintf(codetype, "Switchhook Flash?");
            break;
        case 0x4656ff00:
            sprintf(codetype, "Ignore Rotary Digits?");
            break;
        case 0x4e2eff00:
            sprintf(codetype, "H.320 Conversion?");
            break;
        case 0x6000ff00:
            sprintf(codetype, "Service Link Mode");
            break;
        case 0x6001ff00:
            sprintf(codetype, "Multimedia Mode");
            break;
        case 0x6200ff00:
            sprintf(codetype, "MWI Served User Type");
            break;
        case 0x6604ff00:
            sprintf(codetype, "Recall Rotary Digit?");
            break;
        case 0x0017ff00:
            sprintf(codetype, "Coverage Msg Retrieval?");
            break;
        case 0x0030ff00:
            sprintf(codetype, "Auto Answer");
            break;
        case 0x0014ff00:
            sprintf(codetype, "Data Restriction");
            break;
        case 0x0025ff00:
            sprintf(codetype, "Call Waiting Indication?");
            break;
        case 0x0050ff00:
            sprintf(codetype, "Att. Call Waiting Indication?");
            break;
        case 0x0012ff00:
            sprintf(codetype, "Distinctive Audible Alert?");
            break;
        case 0x007aff00:
            sprintf(codetype, "Adjunct Supervision?");
            break;
        case 0x5800ff00:
            sprintf(codetype, "Per Station CPN - Send Calling Number?");
            break;
        case 0x0fb0ff00:
            sprintf(codetype, "Audible Message Waiting?");
            break;
        case 0x6600ff00:
            sprintf(codetype, "Coverage After Forwarding?");
            break;
        case 0x5801ff00:
            sprintf(codetype, "Multimedia Early Answer?");
            break;
        case 0x0031ff00:
            sprintf(codetype, "Room");
            strncpy(lineinfo.room, token, 10);
            break;
        case 0x0032ff00:
            sprintf(codetype, "Jack");
            break;
        case 0x0033ff00:
            sprintf(codetype, "Cable");
            break;
        case 0x0fa5ff00:
            sprintf(codetype, "Floor");
            break;
        case 0x0fa4ff00:
            sprintf(codetype, "Building");
            break;
        case 0x002fff00:
            sprintf(codetype, "Headset?");
            break;
        case 0x0fa1ff00:
            sprintf(codetype, "Speaker?");
            break;
        case 0x0fa2ff00:
            sprintf(codetype, "Mounting");
            break;
        case 0x0fa3ff00:
            sprintf(codetype, "Cord Length");
            break;
        case 0x0fa6ff00:
            sprintf(codetype, "Set Color");
            break;
        case 0x801f0101:
            sprintf(codetype, "Line Appearance");
            break;
        case 0x002aff00:
            sprintf(codetype, "R Balance Network?");
            break;
        // These result codes are for busy/release commands
        case 0x0001ff00:
            sprintf(codetype, "Port");
            strncpy(lineinfo.port, token, 7);
            break;
        case 0x0002ff00:
            sprintf(codetype, "Maintenance Name");
            break;
        case 0x0005ff00:
            sprintf(codetype, "Alt. Name");
            break;
        case 0x0003ff00:
            sprintf(codetype, "Result");
            strncpy(lineinfo.result, token, 9);
            break;
        case 0x0004ff00:
            sprintf(codetype, "Error Code");
            strncpy(lineinfo.errcode, token, 5);
            break;
        default:
            sprintf(codetype, "%x", code);
    }
    return codetype;
}

char error_parse(char * buffer) {
    // This can simple, since it's pretty much all fixed length fields
    if (strlen(buffer) > 16) {
        fprintf(logfile, "Error: %c\nAdditional data: %c%c%c%c%c%c%c%c\nError code: %c%c%c%c\nError definition: %s\n",\
        buffer[0], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7], buffer[8], buffer[9],\
        buffer[11], buffer[12], buffer[13], buffer[14], buffer+16);
        if(strstr( "has data locked", buffer+16)) return 2;
    }
    else {
        // All the nope
        fprintf(logfile, "Error message returned was abnormal length, cannot parse!\n");
        return 1;
    }
    return 0;
}

char parse_response(char* buffer) {
    // Did the Definity shit the bed? Press one for yes, or two for no.
    //char * token = strtok_r(buffer, "\t\n", &pointer);

    // Given the variance of what the serial port's sending us,
    // we really do need all these checks for token == NULL.
    // Every last one.

    // TO DO: This parser became a little overcomplicated in the interest of getting something
    // out quickly. It should probably be simplified to make it easier to maintain.
    char * last_delimiter;
    char * token = ossi_tokenizer(buffer, &last_delimiter);
    fprintf(logfile, "DEBUG: First tokenizer run succeeded.\n");
    if (token == NULL) {
        fprintf(logfile, "WARNING: Last string detected! Exiting...\n");
        // There's no data, so how do we know if it returned successfully?
        return 1;
    }
    // The first entry's just echoed text; we can skip it.
    //token = strtok_r(NULL, "\t\n", &pointer);
    token = ossi_tokenizer(NULL, &last_delimiter);
    if (*last_delimiter == 0x00) {
        fprintf(logfile, "WARNING: Last string detected! Exiting...\n");
        // There's no data, so how do we know if it returned successfully?
        return 1;
    }
    unsigned char counter = 0;
    char statuscode = 0;
    unsigned char data;
    unsigned char field = 1; // Wasting seven bits, tsk, tsk...
    initialswitch:
    fprintf(logfile, "DEBUG: last_delimiter is %x\n", *last_delimiter);
    if (token == NULL) {
        // We're probably at the EOF
        fprintf(logfile, "WARNING: token is null!\n");
        return statuscode;
    }
    switch(token[0]) {
        case 'c':
            // This is likely an error; a stray command echoed back from the system.
            token = ossi_tokenizer( NULL, &last_delimiter);
            goto initialswitch;
            break;
        case 'f':
            token++; // Offset by one since the first character's a field indicator; not part of the data.
            field = 1;
            break;
        case 'd':
            //printf("Reading data...\n");
            token++;
            field = 0;
            data = counter; // This is going to be erratic, but whatever.
            fprintf(logfile, "Fields for counter stopped at %d\n", counter);
            break;
        case 'e':
            fprintf(logfile, "HOLY FUCK, AN ERROR!\n");
            token++;
            if (error_parse(token) == 2) statuscode = 2;
            else statuscode = 1;
            if (*last_delimiter == 0x0a) {
                token = ossi_tokenizer( NULL, &last_delimiter);
                goto initialswitch;
            }
            break;
        case 't':
            // Yyyyyeah, we should probably stop.

            // Sometimes the Definity decides it wants to be a smartass and echoes the terminator back as
            // the first character. We should account for that here. This only happens at lower baud rates
            // and is ostensibly something to do with how the echo routine handles that.
            if ((*last_delimiter == 0x0a) || (*last_delimiter == 0x09) ) {
                fprintf(logfile, "DEBUG: Definity returned a terminator, but it's full of shit.\n");
                token = ossi_tokenizer( NULL, &last_delimiter);
                goto initialswitch;
            }
            else {
                fprintf(logfile, "Reading input terminator. Function halted early.\n");
                return statuscode;
            }
        default:
            fprintf(logfile, "Reading unknown data. Parse error? Evaluated token was %c\n", token[0]);
    }
    while(token) {
        if(field) {
            // This output's so fucking hard to parse... >.<
            ossifield[counter] = (int)strtol(token, NULL, 16);
            //printf("%d - %s | %s\n", counter, code_identify((int)strtol(token, NULL, 16)), token);
        }
        else {
            fprintf(logfile, "%s - %s\n", code_identify(ossifield[(counter - data)], token), token);
        }
        counter++;
        token = ossi_tokenizer( NULL, &last_delimiter);
        if (token == NULL) {
            fprintf(logfile, "WARNING: token is null!\n");
            return statuscode;
        }

        if (*last_delimiter == 0x0a) {
            // HOLY SHIT THE NEXT TOKEN IS AFTER A LINEBREAK SO MUCH EXCITE
            // Do one iteration of the previous code and then evaluate for a field change
            if(field) ossifield[counter] = (int)strtol(token, NULL, 16);
            else fprintf(logfile, "%s - %s\n", code_identify(ossifield[(counter - data)], token), token);
            counter++;
            innerswitch:
            if (token != NULL) token = ossi_tokenizer( NULL, &last_delimiter);
            else continue;
            switch(token[0]) {
                case 'f':
                    //printf("Reading field...\n");
                    token++; // Offset by one since the first character's a field indicator; not part of the data.
                    field = 1;
                    break;
                case 'd':
                    //printf("Reading data...\n");
                    token++;
                    if (field != 0) {
                        field = 0;
                        data = counter;
                        fprintf(logfile, "DEBUG: Fields for counter stopped at %d\n", counter);
                    }
                    break;
                case 'e':
                    fprintf(logfile, "HOLY FUCK, AN ERROR!\n");
                    token++;
                    error_parse(token);
                    statuscode = 1;
                    if (*last_delimiter == 0x0a) goto innerswitch;
                    else if (*last_delimiter == 0x00) {
                        // Something's going on. We're at the end of the line.
                        return statuscode;
                    }
                    break;
                case 't':
                    // Yyyyyeah, we should probably stop.
                    fprintf(logfile, "Reading input terminator.\n");
                    token = NULL; // This'll stop the loop. No segfaulting for me plz
                    break;
                default:
                    fprintf(logfile, "Reading unknown data. Parse error? Evaluated token was %c\n", token[0]);
            }
        }
        else if (*last_delimiter == 0x00) {
            // We're at the end, just leave.
            fprintf(logfile, "DEBUG: last_delimiter is 0x00. Exiting...\n");
            return statuscode;
        }
    }
    return statuscode;
}

void disp_station(char* station) {
    char query[20];
    // How big is the response actually?
    char response[2000];
    int bytes_read;
    unsigned char trycounter = 0;
    disp_retry:
    snprintf(query, sizeof(query), "cdisp sta %s\rt\r", station);
    // Should this be a strlen instead of sizeof for write()?
    fprintf(logfile, "DEBUG: query is cdisp sta %s\nr\n", station);
    write(fd, query, sizeof(query));
    usleep(1600000);
    // Sometimes with queries sent impossibly fast, the echoing gets erratic, which messes up the
    // parser since it'll see the first line as the terminator being echoed back. This is a fix to
    // hopefully stop that.
    //write(fd, "t\n\r", 3);
    sleep(7); // This query's going to take a while to return
    //usleep(800000); // Wait for the response
    bytes_read = read(fd, response, sizeof(response));
    response[bytes_read] = '\0';
    if (bytes_read == 0) {
        fprintf(logfile, "...shit, nothing returned.\n");
    }
    else {
        fprintf(logfile, "Station query response: %s\n", response);
        char responseval = parse_response(response);
        if (responseval == 2) {
            if (trycounter < 3) {
                // This is ugly, but it'll work.
                fprintf(logfile, "Console was busy, retrying...\n");
                trycounter++;
                sleep(10);
                goto disp_retry;
            }
            fprintf(logfile, "Console is still busy, giving up >.<\n");
        
        }

    }

    return;
}

char busy_station(char* station) {
    //cbus sta xxxx
    char query[22];
    char response[2000];
    unsigned char trycounter = 0;
    busy_retry:
    snprintf(query, sizeof(query), "\r\ncbus sta %s\rt\r", station);
    write(fd, query, sizeof(query));
    usleep(2000000); // Wait for the response
    if (read(fd, response, sizeof(response)) == 0) {
        fprintf(logfile, "...shit, nothing returned.\n");
    }
    else {
        fprintf(logfile, "Busy response: %s\n", response);
    }

    char responseval = parse_response(response);
    if (responseval == 1) {
        fprintf(logfile, "Busy station failed!\n");
    }
    else if (responseval == 2) {
        if (trycounter < 3) {
            // This is ugly, but it'll work.
            fprintf(logfile, "Console was busy, retrying...\n");
            trycounter++;
            sleep(10);
            goto busy_retry;
        }
        fprintf(logfile, "Console is still busy, giving up >.<\n");
        
    }

    fprintf(logfile, "DEBUG: Result code for operation is %s\n", lineinfo.result);
    if (strlen(lineinfo.result) > 1) {
        if (strcmp("PASS", lineinfo.result) != 0) return 1;
    }
    return 0;
}

void rel_station(char* station) {
    //crel sta xxxx
    char query[20];
    char response[2000];
    int bytes_read;
    unsigned char trycounter = 0;
    snprintf(query, sizeof(query), "crel sta %s\rt\r", station);
    rel_retry:
    write(fd, query, sizeof(query));
    sleep(4); // This takes a really long time to complete
    bytes_read = read(fd, response, sizeof(response));
    response[bytes_read] = '\0';
    fprintf(logfile, "Release response: %s\n", response);
    char responseval = parse_response(response);
    if (responseval == 1) {
        fprintf(logfile, "Busy station failed!\n");
    }
    else if (responseval == 2) {
        if (trycounter < 3) {
            // This is ugly, but it'll work.
            fprintf(logfile, "Console was busy, retrying...\n");
            trycounter++;
            sleep(10);
            goto rel_retry;
        }
        fprintf(logfile, "Console is still busy, giving up >.<\n");
        
    }

    fprintf(logfile, "DEBUG: Result code for operation is %s\n", lineinfo.result);
    return;
}

void remove_station(char * station) {
    //crem sta xxxx
    char query[20];
    char response[2000];
    unsigned char trycounter = 0;
    char responseval;
    int bytes_read;
    snprintf(query, sizeof(query), "crem sta %s\rt\r", station);
    remove_retry:
    write(fd, query, sizeof(query));
    usleep(1600000); // Wait for the response
    bytes_read = read(fd, response, sizeof(response));
    response[bytes_read] = '\0';
    fprintf(logfile, "Remove response: %s\n", response);
    
    responseval = parse_response(response);

    if (responseval == 1) {
        fprintf(logfile, "Busy station failed!\n");
    }
    else if (responseval == 2) {
        if (trycounter < 3) {
            // This is ugly, but it'll work.
            fprintf(logfile, "Console was busy, retrying...\n");
            trycounter++;
            sleep(10);
            goto remove_retry;
        }
        fprintf(logfile, "Console is still busy, giving up >.<\n");
        
    }
    return;
}

void add_station(char * station) {
    //cadd sta xxxx
    char query[126];
    char response[2000];
    char responseval;
    unsigned char trycounter = 0;
    int bytes_read;
    if (strlen(lineinfo.name) < 1) sprintf(lineinfo.name, "Auto-provisioned Station");
    snprintf(query, sizeof(query), "\r\ncadd sta %s\rf004fff00\rd%s\rf8004ff00\rd%s\rf8003ff00\rd%s\rf0011ff00\rd%c\rf007aff00\rdy\rt\r", station, lineinfo.type, lineinfo.port, lineinfo.name, lineinfo.attributes & 1 ? 'y' : 'n');
    fprintf(logfile, "DEBUG: was cadd sta %s\nf004fff00\nd%s\nf8004ff00\nd%s\nf8003ff00\nd%s\nf0011ff00\nd%c\nf007aff00\ndy\nt\n", station, lineinfo.type, lineinfo.port, lineinfo.name, lineinfo.attributes & 1 ? 'y' : 'n');
    add_retry:
    write(fd, query, sizeof(query));
    usleep(2100000);

    // Sometimes with queries sent impossibly fast, the echoing gets erratic, which messes up the
    // parser since it'll see the first line as the terminator being echoed back. This is a fix to
    // hopefully stop that.

    bytes_read = read(fd, response, sizeof(response));
    response[bytes_read] = '\0';
    fprintf(logfile, "Add response: %s\n", response);
    responseval = parse_response(response);
    if (responseval == 1) {
        fprintf(logfile, "Add station failed!\n");
    }
    else if (responseval == 2) {
        if (trycounter < 3) {
            // This is ugly, but it'll work.
            fprintf(logfile, "Console was busy, retrying...\n");
            trycounter++;
            sleep(10);
            goto add_retry;
        }
        fprintf(logfile, "Console is still busy, giving up >.<\n");
        
    }
    return;
}

char moveline(char * src, char * dest) {
    fprintf(logfile, "Querying station...\n");
    disp_station(src);
    if (strlen(lineinfo.port) > 1) {

        fprintf(logfile, "Busying station...\n");
        if (busy_station(src) != 0){
            fprintf(logfile, "ERROR: Busying station failed! Releasing station and halting operation.\n");
            rel_station(src);
            return 1;
        }

        else {
            // If this is a request to just busy the line, we can stop here.
            if (dest[0] == 'B') {
                fprintf(errorfile, "%s - NOTICE: Busied out some asshole's phone line: %s\n", timeoutput(), src);
                fflush(errorfile);
                fprintf(logfile, "Busy-only order completed!\n");
                return 0;
            }
            fprintf(logfile, "Removing station...\n");
            remove_station(src);
            fprintf(logfile, "Adding station...\n");
            add_station(dest);
        }
    }

    else {
        fprintf(logfile, "ERROR: Station query returned no logical port! Cannot proceed with station move.\n");
        return 1;
    }
    return 0;
}

char modemdial(char * atstring) {
     // Send the dial command to the modem
    write(fd, atstring, strlen(atstring));

    // For the moment, it's assumed we'll need to memorize the modem signals from before
    // to restore modem state upon exit, so we can't just reuse them here.
    int modem_status;
    fprintf(logfile, "Dial successful. Waiting for carrier...\n");

    // Pre-C99 standards don't allow declarations of variables inside a for loop.
    // This was moved to right before the for loop for compatibility.

    unsigned char counter;
    for(counter = 0; counter < 30; counter++) {
        if (ioctl(fd, TIOCMGET, &modem_status) == -1) {
            fprintf(logfile, "ERROR: Can't get modem status! Errno %d\n", errno);
            return 1;
        }
        // When we see carrier detect, knock this shit off and keep going
        if (modem_status & TIOCM_CD) return 0;
        sleep(1);
    }
    fprintf(logfile, "Modem timed out waiting for carrier\n");
    return 1;
}

char orderparse(char * parsefile, char * sourcenum, char * destnum, char * dialstring, char * altstring) {
    FILE* orderfd;
    orderfd = fopen(parsefile, "r");
    void * mem;
    char * token;

    if (orderfd == NULL) {
        fprintf(errorfile, "ERROR: Couldn't open parsefile %s!\n", parsefile);
        return 1;
    }
    // Use fread() to get file contents here. See chttpd.c for example.
    // strtok() here.
    long ordersize = fsize(orderfd);
    mem = malloc(ordersize);
    if (mem == NULL) {
        fprintf(errorfile, "ERROR: Memory could not be allocated for parsing order file!\n");
        return 1;
    }

    if ((fread(mem, 1, ordersize, orderfd)) != ordersize) {
        if(feof(orderfd)) {
            fprintf(errorfile, "ERROR: Couldn't read %s! Unexpected end of file\n", parsefile);
        }

        else if (ferror(orderfd)) {
            fprintf(errorfile, "ERROR: Coudln't read %s!\n", parsefile);
        }

        else {
            fprintf(errorfile, "ERROR: Unknown error reading %s!\n", parsefile);
        }
        free(mem);
        fprintf(errorfile, "%s - Unknown error reading %s\n", timeoutput(), parsefile);
        fflush(errorfile);
        fclose(orderfd);
        return 1;
    }
    if (logfile != NULL)
    fprintf(logfile, "DEBUG: Successfully read %s!\n", parsefile);
    fclose(orderfd);

    // No loop for this one, so it's going to look a little ugly.
    // Not as bad as the OSSI parser though.

    // sourcenum
    token = strtok(mem, ",");
    if (token == NULL) {
        fprintf(errorfile, "ERROR: Couldn't find sourcenum in order file %s!\n", parsefile);
        free(mem);
        return 1;
    }
    strncpy(sourcenum, token, 8);

    //destnum
    token = strtok(NULL, ",");
    if (token == NULL) {
        fprintf(errorfile, "ERROR: Couldn't find destnum in order file %s!\n", parsefile);
        free(mem);
        return 1;
    }
    strncpy(destnum, token, 8);

    //dialstring
    token = strtok(NULL, ",");
    if (token == NULL) {
        fprintf(errorfile, "ERROR: Couldn't find dialstring in order file %s!\n", parsefile);
        free(mem);
        return 1;
    }
    if (dialstring != NULL) strncpy(dialstring, token, 27);

    //altstring
    token = strtok(NULL, ",");
    if (token == NULL) {
        fprintf(errorfile, "ERROR: Couldn't find altstring in order file %s!\n", parsefile);
        free(mem);
        return 1;
    }
    if (altstring != NULL) strncpy(altstring, token, 27);

    // We done here? Cool.
    free(mem);
    return 0;
}

void modem_loop(char * logfilename, char * orderfilename) {
    // The ISR, when doing modem to telnet bridging, is going to want to see a CR.
    // A real terminal line to the Definity isn't going to care as much.
    sleep(10);
    //usleep(200000); // Wait for the response
    // Read the response from the modem
    int bytes_read = read(fd, buffer, MODEM_RESPONSE_BUFFER_SIZE);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        fprintf(logfile, "Modem response: %s\n", buffer);
        if (strstr(buffer, "CONNECT")) {
            fprintf(logfile, "Hey, we connected!\n");
            sleep(1);
            write(fd, "\r", 1); // Hit enter
            //usleep(200000); // Wait for the response
            //bytes_read = read(fd, buffer, MODEM_RESPONSE_BUFFER_SIZE);
        }
    } else {
        fprintf(logfile, "No response from the modem\n");
    }
    while (bytes_read > 0) {
        //usleep(100000); // Wait for the response
        sleep(2);
        bytes_read = read(fd, buffer, MODEM_RESPONSE_BUFFER_SIZE);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            if (strstr(buffer, "Login:")) {
                fprintf(logfile, "We're at a Definity login prompt. Sending login...\n");
                write(fd, "hatbowls\r", 6);
                // The usleep commands need to be sent with care; sometimes the data takes a
                // few seconds to complete the transmission. Especially since the testing
                // environment involves sending it over the internet
                usleep(800000); // Wait for the response
                read(fd, buffer, MODEM_RESPONSE_BUFFER_SIZE);
                if (strstr(buffer, "Password:")) {
                    fprintf(logfile, "Hey, a password prompt!\n");
                    write(fd, "b0wlerhat\r", 7);
                }
                else continue;
                usleep(2400000); // Wait for the response
                //sleep(5);
                read(fd, buffer, MODEM_RESPONSE_BUFFER_SIZE);
                if (strstr(buffer, "Terminal Type")) {
                    fprintf(logfile, "Login successful! It's asking us for a terminal type!\n");
                    write(fd, "ossi\r", 5);
                    //sleep(1);
                    usleep(600000); // Wait for the response
                    read(fd, buffer, MODEM_RESPONSE_BUFFER_SIZE);
                    if(strstr(buffer, "\nt")) { // For new lines, Definity sends form feeds
                        fprintf(logfile, "THE SWITCH IS READY FOR INPUT!!!! HOLY FUCKING HATSAUCE!!11\n");
                    }

                    if (moveline( sourcenum, destnum) == 0) {
                        // If the move succeeded, while we're still connected, we should see about adding some more lines.

                        remove(orderfilename);
                        struct dirent *direntry;
                        DIR *directory = opendir(dialstring);

                        if (directory == NULL) {
                            // The directory doesn't exist, let's just get out of here.
                            fprintf(logfile, "DEBUG: Directory doesn't exist. Exiting...\n");
                            break;
                        }
                        else {
                            // TO DO: This code was exhibiting some weird bug at Toorcamp when there were a lot of files in a directory.
                            // The software still worked, but it negatively impacted its ability to provision multiple lines in a single
                            // session. This should be reproduced and fixed.
                            while((direntry = readdir(directory)) != NULL) {
                                if (strstr(direntry->d_name, ".ord")) {
                                    // Zero out the memory structure for a Definity
                                    // line, just in case.
                                    memset(&lineinfo, 0x00, sizeof(DEFLINE));
                                    snprintf(orderfilename, sizeof(orderfilename), "%s/%s", dialstring, direntry->d_name);
                                    if (orderparse(orderfilename, sourcenum, destnum, NULL, NULL) != 0) {
                                        continue;
                                    }
                                    fclose(logfile); // Close the old log file and open one for this new order
                                    snprintf(logfilename, 39, "%s/%s.log", dialstring, sourcenum);
                                    logfile = fopen(logfilename, "a+");
                                    if (logfile == NULL) {
                                        fprintf(stderr, "ERROR: Cannot open log file!");
                                        fprintf(errorfile, "%s - Cannot open log file %s\n", timeoutput(), logfilename);
                                        fflush(errorfile);
                                        closedir(directory);
                                        fclose(errorfile);
                                        close(fd);
                                        exit(1);
                                    }
                                    // Delay increased; there were some issues with the modem not always completing on time
                                    usleep(900000); // Wait for the response destnum);
                                    write(fd, "\r\n", 2); // Hit enter
                                    usleep(900000); // Wait for the response destnum);
                                    //sleep(1);
                                    if (moveline( sourcenum, destnum ) != 0) {
                                        fprintf(logfile, "ERROR: Line provisioning failure!\n");
                                        // Let's borrow this string for a sec.
                                        snprintf(logfilename, 39, "%s/%s.err", dialstring, sourcenum);
                                        rename(orderfilename, logfilename);
                                        break;
                                    }
                                    remove(orderfilename);
                                }
                            }
                            closedir(directory);
                            fprintf(logfile, "DEBUG: Batch provisioning via directory complete.\n");

                        }
                    }
                    else {
                        // Error processing for primary order
                        snprintf(logfilename, 39, "%s/%s.err", dialstring, sourcenum);
                        rename(orderfilename, logfilename);
                    }

                    continue;
                }
                else {
                    fprintf(logfile, "DEBUG: This came in from the modem, and it has nothing that looks like a request for terminal type: %s\n", buffer);
                    continue;
                }
            }
            else {
                fprintf(logfile, "Modem response: %s\n", buffer);
            }
        } else {
            fprintf(logfile, "End of DCE response. Exiting...\n");
        }
    }
    return;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("USAGE: %s [orderfile]\n", argv[0]);
        return 1;
    }
    char orderfile[260];
    char logfilename[39];

    errorfile = fopen("provision_errors.log", "a+");
    if (errorfile == NULL) {
        fprintf(stderr, "ERROR: Cannot open error log file!\n");
        return 1;
    }

    fprintf(errorfile, "This is a test of the provision_errors log\n");

    if (orderparse(argv[1], sourcenum, destnum, dialstring, altstring) != 0) {
        fclose(errorfile);
        return 1;
    }

    snprintf(logfilename, 39, "%s/%s.log", dialstring, sourcenum);

    logfile = fopen(logfilename, "w");
    if (logfile == NULL) {
        fprintf(stderr, "ERROR: Cannot open log file!\n");
        fclose(logfile);
        fclose(errorfile);
        return 1;
    }

    // Open the serial port
    fd = open(SERIAL_PORT, O_RDWR | O_NOCTTY | O_NDELAY);
    if (fd == -1) {
        fprintf(logfile, "ERROR: Can't open serial port!\n");
        fprintf(errorfile, "%s - Could not open serial port\n", timeoutput());
        fflush(errorfile);
        perror("open");
        fclose(logfile);
        fclose(errorfile);
        return 1;
    }



    // Configure the serial port settings
    //memset(&serial_settings, 0, sizeof(serial_settings));
    // Zeroing out is bad juju! This has been causing driver issues.

    if (tcgetattr( fd, &serial_settings) != 0) {
        fprintf(errorfile, "tcgetattr returned error %d!\n", errno);
        fflush(errorfile);
        fclose(logfile);
        fclose(errorfile);
        return 1;
    }

    cfsetospeed( &serial_settings, BAUDRATE);
    cfsetispeed( &serial_settings, BAUDRATE);

    //serial_settings.c_cc[VTIME] = 255; // in tenths of a second
    serial_settings.c_cc[VMIN]  = 1;            // read blocks
    serial_settings.c_cc[VTIME] = 5;            // 0.5 seconds read timeout
    //serial_settings.c_cflag = BAUDRATE | CS8 | CREAD | CRTSCTS;
    serial_settings.c_cflag = CS8 | CREAD | CRTSCTS | CLOCAL; // Baud rate is set with the functions above now.
    // CLOCAL stops this library from completely losing its shit when we deassert DTR using an ioctl in disconnect_modem()
    serial_settings.c_iflag = IGNPAR;
    //serial_settings.c_iflag &= ~(IXON|IXOFF|IXANY); // Turn off any software flow control
    serial_settings.c_oflag = 0;
    serial_settings.c_lflag = 0;
    tcflush(fd, TCIFLUSH);
    tcsetattr(fd, TCSANOW, &serial_settings);
    // In practice, the modem takes a second to get going; it's not always
    // immediately ready to accept input. 1 second should be plenty for it
    // to gather its bearings.
   
    // Set DTR signal
    ioctl(fd, TIOCMGET, &modem_signals);
    modem_signals |= (TIOCM_DTR | TIOCM_RTS);
    ioctl(fd, TIOCMSET, &modem_signals);

    sleep(1);
    // The order file parser should do this now.
    char atstring[31];
    snprintf(atstring, 31, "ATDT%s\r", dialstring);
    if (modemdial(atstring) == 1) {
        close(fd);
        fclose(logfile);
        fprintf(errorfile, "%s - Failed to dial phone number: %s\n", timeoutput(), dialstring);
        fflush(errorfile);
        fclose(errorfile);
        return 1;
    }

    modem_loop(logfilename, argv[1]);

    disconnect_modem();
    sleep(1);
    close(fd);
    // Give it a second to collect its bearings.

    // Workaround. The Linux serial code is absolutely losing its shit
    // after we disconnect, so for the moment, we're closing and re-opening
    // the port.

    // While I can't prove it, this is likely related to some control line
    // the modem is deasserting.

    fd = open(SERIAL_PORT, O_RDWR | O_NOCTTY | O_NDELAY);
    if (fd == -1) {
        fprintf(logfile, "ERROR: Can't open serial port!\n");
        perror("open");
        fprintf(errorfile, "%s - Can't open serial port!\n", timeoutput());
        fflush(errorfile);
        fclose(logfile);
        fclose(errorfile);
        return 1;
    }

    sleep(1); // Give the modem a second to get going

    // Some modems are acting erratically, so the code from the top was pasted in

    if (tcgetattr( fd, &serial_settings) != 0) {
        fprintf(errorfile, "tcgetattr returned error %d!\n", errno);
        fflush(errorfile);
        fclose(logfile);
        fclose(errorfile);
        return 1;
    }

    cfsetospeed( &serial_settings, BAUDRATE);
    cfsetispeed( &serial_settings, BAUDRATE);

    //serial_settings.c_cc[VTIME] = 255; // in tenths of a second
    serial_settings.c_cc[VMIN]  = 1;            // read blocks
    serial_settings.c_cc[VTIME] = 5;            // 0.5 seconds read timeout
    //serial_settings.c_cflag = BAUDRATE | CS8 | CREAD | CRTSCTS;
    serial_settings.c_cflag = CS8 | CREAD | CRTSCTS; // Baud rate is set with the functions above now.
    serial_settings.c_iflag = IGNPAR;
    serial_settings.c_iflag &= ~(IXON|IXOFF|IXANY); // Turn off any software flow control
    serial_settings.c_oflag = 0;
    serial_settings.c_lflag = 0;
    tcflush(fd, TCIFLUSH);
    tcsetattr(fd, TCSANOW, &serial_settings);

    // Set DTR signal
    if (ioctl(fd, TIOCMGET, &modem_signals) == -1) {
        fprintf(logfile, "TIOCMGET fail! Errno %d\n", errno);
    }
    modem_signals |= (TIOCM_DTR | TIOCM_RTS);
    ioctl(fd, TIOCMSET, &modem_signals);

    if (altstring != NULL) {

        struct dirent *direntry;
        DIR *directory = opendir(altstring);
        if (directory == NULL) {
            fprintf(logfile, "DEBUG: Alternate directory doesn't exist. Exiting...\n");
            close(fd);
            fclose(logfile);
            fclose(errorfile);
            return 0;
        }

        while((direntry = readdir(directory)) != NULL) {
            if (strstr(direntry->d_name, ".ord")) {
                memset(&lineinfo, 0x00, sizeof(DEFLINE));
                snprintf(orderfile, 260, "%s/%s", altstring, direntry->d_name);

                if (orderparse(orderfile, sourcenum, destnum, dialstring, NULL) != 0) {
                    fprintf(logfile, "ERROR: Couldn't parse order file! Exiting...\n");
                    closedir(directory);
                    close(fd);
                    fprintf(errorfile, "%s() - Couldn't parse order file %s\n", timeoutput(), orderfile);
                    fflush(errorfile);
                    fclose(logfile);
                    fclose(errorfile);
                    return 1;
                }

                // At this point, we can confirm we have a readable order file in the
                // alternate directory. Let's re-invoke all that crap.

                snprintf(atstring, 31, "ATDT%s\r", dialstring);
                if (modemdial(atstring) == 1) {
                    close(fd);
                    fprintf(errorfile, "%s - Failed to dial phone number: %s\n", timeoutput(), dialstring);
                    fflush(errorfile);
                    fclose(logfile);
                    fclose(errorfile);
                    return 1;
                }
                modem_loop(logfilename, orderfile);
                break;
            }
        }
        disconnect_modem();
        sleep(1);
        closedir(directory);
    }

    // Deassert DTR and close the serial port
    close(fd);
    fclose(logfile);
    fclose(errorfile);
    return 0;
}
