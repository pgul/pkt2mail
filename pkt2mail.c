/* --------------------------------------------------------------------------
 * PKT-TO-MAIL v0.2                                           Mar 25th, 2000
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

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include <fidoconf/fidoconf.h>

#include "pkt2mail.h"
#include "mime.c"

int log(char *string, s_fidoconfig *c, int level)
{
    char *name;
    char date[40];
    FILE *logFile;
    time_t t;

    if (c->loglevels[0] == 0 || strchr(c->loglevels, level+'0') != NULL) {
        time(&t);
        strftime(date, 40, "%a %d %b  %H:%M:%S", localtime(&t));

        if ((name = malloc(strlen(c->logFileDir) + 13)) == NULL)
            return -2;

        sprintf(name, "%spkt2mail.log", c->logFileDir);

        if ((logFile = fopen(name, "a")) == NULL)
            return -1;
        fprintf(logFile, "%d   %s   %s", level, date, string);
        fclose(logFile);
    }

    return 0;
}



int printBody(FILE *output)
{
    int c;
    char *name;
    FILE *desc;

    name = malloc(strlen(CFGDIR)+14);

    strcpy(name, CFGDIR);
    if (name[strlen(name)] != '/')
        sprintf(name, "%s/pkt2mail.msg", CFGDIR);
    else
        sprintf(name, "%spkt2mail.msg", CFGDIR);

    if ((desc = fopen(name, "r")) == NULL)
        return 1;
        
    while ((c = fgetc(desc)) != EOF)
        putc(c, output);
    fclose(desc);

    return 0;
}

int encodeAndSend(s_fidoconfig *c, char *fileName, int n)
{
    char buff[255];
    char random[10];
    char realFileName[255];
    char *s;

    FILE *input;
    FILE *output;

    /* get the fileName */
    strcpy(realFileName, fileName);
    if ((s = strrchr(fileName, '/')))
        fileName = s + 1;

    /* change the name to a pseudo-random name!
     * Actually, this would be a msgid-like routine, but
     * it is not worth, beacause the receiving system should
     * cope with same file names (mail2pkt does) */
    sprintf(random, "%04x", (unsigned int)time(0));
     
    if (fileName[10] == 'u' && fileName[11] == 't')
        sprintf(fileName, "%s.pkt", random);   /* a netmail pkt */

    /* Normally, we wouldn't need to change an echomail bundle's name...
     * if so, just uncomment the following lines */
/*    else
        sprintf(fileName, "%s%s", random, fileName+8);*/

    sprintf(buff, "%s%s", c->tempOutbound, random);
    if ((output = fopen(buff, "wt")) == NULL) {
        sprintf(buff, "[!] Can't write to %s%s\n", c->tempOutbound, random);
        log(buff, c, 1);
        return 1;
    }
    if ((input = fopen(realFileName, "r")) == NULL) {
        sprintf(buff, "[!] Can't read from %s\n", realFileName);
        log(buff, c, 1);
        return 2;
    }

    /* print some headers */
    fprintf(output, "X-Mailer: pkt2mail v%s\n", VERSION);
    fprintf(output, "From: \"%s\"\n", c->sysop);
    fprintf(output, "To: %s\n", c->links[n].email);
    fprintf(output, "Subject: %s: %d:%d/%d.%d -> %d:%d/%d.%d\n", SUBJECT,
                                                           c->links[n].ourAka->zone,
                                                           c->links[n].ourAka->net,
                                                           c->links[n].ourAka->node,
                                                           c->links[n].ourAka->point,
                                                           c->links[n].hisAka.zone,
                                                           c->links[n].hisAka.net,
                                                           c->links[n].hisAka.node,
                                                           c->links[n].hisAka.point);

    fprintf(output, "Mime-Version: 1.0\n");
    fprintf(output, "Content-Type: multipart/mixed; boundary=\"-pkt2mailboundary\"\n\n");
    fprintf(output, "This MIME encoded message is a FTN packet created by\n");
    fprintf(output, "PKT2MAIL, available at http://husky.physcip.uni-stuttgart.de\n");
    fprintf(output, "Decode it with MAIL2PKT or any MUA supporting mime.\n");

    fprintf(output, "\n---pkt2mailboundary\n\n");

    /* now the text */
    if (printBody(output) == 1) {
        sprintf(buff, "[!] Can't read from %spkt2mail\n", CFGDIR);
        log(buff, c, 1);
        return 3;
    }
        
    fprintf(output, "\n---pkt2mailboundary\n");

    /* and finally the encoded file */
    fprintf(output, "Content-Type: application/octet-stream; name=\"%s\"\n", fileName);
    fprintf(output, "Content-Transfer-Encoding: base64\n");
    fprintf(output, "Content-Disposition: inline; filename=\"%s\"\n\n", fileName);

    toBase64(input, output);

    fprintf(output, "\n---pkt2mailboundary-");

    fclose(output);
    fclose(input);

    sprintf(buff, "%s %s < %s%s", SENDMAIL, c->links[n].email, c->tempOutbound, random);
    if (system(buff) != 0) {
        log("[!] Error while calling sendmail!\n", c, 1);
        log(strcat(buff, "\n"), c, 1);
        return -1;
    }

    sprintf(buff, "%s%s", c->tempOutbound, random);
    remove(buff);
    remove(realFileName);

    return 0;

}

int processEcho(s_fidoconfig *c, int n)
{
    FILE *flowFile;

    char flowName[16];
    char pntDir[32];
    char zoneSuffix[8];
    char flavourSuffix[8];
    char fullPath[127];

    char pktName[255];
    char buffer[255];

    if (c->links[n].echoMailFlavour == normal)
        strcpy(flavourSuffix, "flo");
    else {
        sprintf(buffer, "Skipping %s, has not normal echomail flavour\n", c->links[n].email);
        log(buffer, c, 2);
        return 2;
    }
	 
    if (c->links[n].hisAka.point != 0) {
        sprintf(pntDir, "%04x%04x.pnt/", c->links[n].hisAka.net, c->links[n].hisAka.node);
        sprintf(flowName, "%08x.%s", c->links[n].hisAka.point, flavourSuffix);
    } else {
        pntDir[0] = 0;
        sprintf(flowName, "%04x%04x.%s", c->links[n].hisAka.net, c->links[n].hisAka.node, flavourSuffix);
    }

    if (c->links[n].hisAka.zone != c->addr[0].zone) {
        sprintf(zoneSuffix, ".%03x/", c->links[n].hisAka.zone);
    } else {
        zoneSuffix[0] = 0;
    }

    sprintf(fullPath, "%s%s%s%s", c->outbound, zoneSuffix, pntDir, flowName);

    flowFile = fopen(fullPath, "rb");
    if (flowFile != NULL) {
        while (fgetc(flowFile) == '^') {
            fgets(pktName, 255, flowFile);
            strip(pktName);   /* remove the final \n */

            if (encodeAndSend(c, pktName, n) == 0)
                if (c->links[n].hisAka.point != 0) {
                    sprintf(buffer, "Sending echomail to %s (%d:%d/%d.%d)\n", c->links[n].email,
                                                           c->links[n].hisAka.zone,
                                                           c->links[n].hisAka.net,
                                                           c->links[n].hisAka.node,
                                                           c->links[n].hisAka.point);
                    log(buffer, c, 1);
                } else {
                    sprintf(buffer, "Sending echomail to %s (%d:%d/%d)\n", c->links[n].email,
                                                           c->links[n].hisAka.zone,
                                                           c->links[n].hisAka.net,
                                                           c->links[n].hisAka.node);
                    log(buffer, c, 1);
                }
            else
                return 1;
        }

        fclose(flowFile);
        remove(fullPath);     /* delete the flow file */
    }

    return 0;

}

int processNetmail(s_fidoconfig *c, int n)
{
    FILE *pktFile;

    char pktName[16];
    char pntDir[32];
    char zoneSuffix[8];
    char flavourSuffix[8];
    char fullPath[128];

    char buffer[255];

    /* only route crash netmail, this can change in the future */
    strcpy(flavourSuffix, "cut");

    if (c->links[n].hisAka.point != 0) {
        sprintf(pntDir, "%04x%04x.pnt/", c->links[n].hisAka.net, c->links[n].hisAka.node);
        sprintf(pktName, "%08x.%s", c->links[n].hisAka.point, flavourSuffix);
    } else {
        pntDir[0] = 0;
        sprintf(pktName, "%04x%04x.%s", c->links[n].hisAka.net, c->links[n].hisAka.node, flavourSuffix);
    }

    if (c->links[n].hisAka.zone != c->addr[0].zone) {
        sprintf(zoneSuffix, ".%03x/", c->links[n].hisAka.zone);
    } else {
        zoneSuffix[0] = 0;
    }

    sprintf(fullPath, "%s%s%s%s", c->outbound, zoneSuffix, pntDir, pktName);
    if ((pktFile = fopen(fullPath, "r")) != NULL) {
        fclose(pktFile);

        if (encodeAndSend(c, fullPath, n) == 0)
            if (c->links[n].hisAka.point != 0) {
                sprintf(buffer, "Sending netmail to %s (%d:%d/%d.%d)\n", c->links[n].email,
                                                      c->links[n].hisAka.zone,
                                                      c->links[n].hisAka.net,
                                                      c->links[n].hisAka.node,
                                                      c->links[n].hisAka.point);
                log(buffer, c, 1);
            } else {
                sprintf(buffer, "Sending netmail to %s (%d:%d/%d)\n", c->links[n].email,
                                                      c->links[n].hisAka.zone,
                                                      c->links[n].hisAka.net,
                                                      c->links[n].hisAka.node);
                log(buffer, c, 1);
            }
        else
            return 1;

        remove(fullPath);
    }

    return 0;
}

int send(s_fidoconfig *c)
{
    int i;
    
    /* for every link in fidoconfig... */
    for (i = 0; i < c->linkCount; i++)
        /* that has an email address... */
        if (c->links[i].email) {
            if (processEcho(c, i) == 1)
                return 1;

            if (processNetmail(c, i) == 1)
                return 2;
        }

    return 0;
}

int main(void)
{
    s_fidoconfig *config;
    int error;

    if ((config = readConfig()) == NULL) {
        log("[!] Error reading config file.\n", config, 1);
        return -1;
    }

    log("pkt2mail started...\n", config, 3);

    error = send(config);
    
    switch (error) {
        case 0:
            log("pkt2mail finnished OK\n", config, 3);
            break;
        case 1:
            fprintf(stderr, "Error processing echomail. See logs for details.\n");
            log("[!] Error processing echomail.\n", config, 1);
        break;
        case 2:
            fprintf(stderr, "Error processing netmail. See logs for details.\n");
            log("[!] Error processing netmail.\n", config, 1);
        break;
        
    }

    return error;
    

}


