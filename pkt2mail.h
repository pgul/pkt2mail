/* --------------------------------------------------------------------------
 * PKT-TO-MAIL v0.2                                            Mar 25th, 2000
 * --------------------------------------------------------------------------
 *   
 *   This program routes via email any FTN Network packet, with MIME64
 *   encoding.
 *
 *   Copyright (C) 1999-2000  German Theler
 *       Email: german@linuxfreak.com
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

#ifndef CFGDIR
  #define CFGDIR  "/etc/fido/"
#endif

/* A text string that defines the email subject*/
#define SUBJECT   "FidoNet Packet"

/* Full path to the sendmail binary. This can be a symlink! */
#define SENDMAIL  "/usr/sbin/sendmail"



#define VERSION   "0.2"
#define strip(s)  s[strlen(s)-1] = 0

int log(char *string, s_fidoconfig *c, int level);
int printBody(FILE *output);
int encodeAndSend(s_fidoconfig *c, char *fileName, int n);
int processEcho(s_fidoconfig *c, int n);
int porcessNetmail(s_fidoconfig *c, int n);
int send(s_fidoconfig *c);
int main(void);
