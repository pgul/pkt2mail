/* --------------------------------------------------------------------------
 * PKT-TO-MAIL v0.2                                            Jan 30th, 2000
 * --------------------------------------------------------------------------
 *   
 *   This program routes via email any FTN Network packet, with MIME64
 *   encoding.
 *
 *   Copyright (C) 1999-2000  German Theler
 *       Email: kuroshivo@bigfoot.com
 *        Fido: 4:905/210
 *
 * 
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation version 2.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * --------------------------------------------------------------------------  
 */

/* Full path to a text file that will be used as the email body */
#define DESCFILE  "/etc/fido/pkt2mail.msg"
//#define DESCFILE  "/home/fido/cfg/pkt2mail.msg"

/* A text string that defines the email subject*/
#define SUBJECT   "FidoNet Packet"

/* Full path to the sendmail binary. This can be a symlink! */
#define SENDMAIL  "/usr/sbin/sendmail"



#define VERSION   "0.2"
#define strip(s)  s[strlen(s)-1] = 0

/* pkt2mail.c */

int log(char *string, char *dir);
int printBody(FILE *output);
int encodeAndSend(s_fidoconfig *c, char *fileName, int n);
int processEcho(s_fidoconfig *c, int n);
int porcessNetmail(s_fidoconfig *c, int n);
int send(s_fidoconfig *c);
int main(void);

/* mime.c */

int to64(FILE *infile, FILE *outfile);
void output64chunk(int c1, int c2, int c3, int pads, FILE *outfile);
