/* --------------------------------------------------------------------------
 * PKT-TO-MAIL v0.1                                           Nov 29th, 1999
 * --------------------------------------------------------------------------
 *   
 *   This program routes via email any FTN Network packet, with MIME64
 *   encoding. Requires smapilnx and fidoconfig libraries to compile.
 *
 *   Copyright (C) 1999  German Theler
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

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include <fidoconfig.h>

#include "pkt2mail.h"
#include "mime.c"

int printBody(FILE *output)
{
    int c;
    FILE *desc;

    if ((desc = fopen(DESCFILE, "r")) == NULL)
        return 1;
        
    while ((c = fgetc(desc)) == EOF)
        putc(c, output);
    fclose(desc);

    return 0;
}

int encodeAndSend(s_fidoconfig *c, char *fileName, int n)
{
    char buff[255];
    char realFileName[255];
    char *s;

    FILE *input;
    FILE *output;

    /* get the fileName */
    strcpy(realFileName, fileName);
    if ((s = strrchr(fileName, '/')))
        fileName = s + 1;

    /* if it is a netmail pkt */
    if (fileName[10] == 'u' && fileName[11] == 't')
        sprintf(fileName, "%04x.pkt", (unsigned int)time(0));


    sprintf(buff, "%spkt2mail", c->tempOutbound);
    if ((output = fopen(buff, "wt")) == NULL)
        return 1;
    if ((input = fopen(realFileName, "r")) == NULL)
        return 2;

    fprintf(output, "Mime-Version: 1.0\n");
    fprintf(output, "Subject: %s\n", SUBJECT);
    fprintf(output, "Content-Type: multipart/mixed; boundary=\"-pkt2mailboundary\"\n\n");
    fprintf(output, "This MIME encoded message is a FTN packet created by\n");
    fprintf(output, "PKT2MAIL. Available at http://www.rafaela.com/fido/email");

    fprintf(output, "\n---pkt2mailboundary\n\n");

    if (printBody(output) == 1)
        return 3;
        
    fprintf(output, "\n---pkt2mailboundary\n");

    fprintf(output, "Content-Type: application/octet-stream; name=\"%s\"\n", fileName);
    fprintf(output, "Content-Transfer-Encoding: base64\n");
    fprintf(output, "Content-Disposition: inline; filename=\"%s\"\n\n", fileName);

    to64(input, output);

    fprintf(output, "\n---pkt2mailboundary-");

    fclose(output);
    fclose(input);

    sprintf(buff, "%s %s < %spkt2mail", SENDMAIL, c->links[n].email, c->tempOutbound);
    system(buff);

    sprintf(buff, "%spkt2mail", c->tempOutbound);
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
    char fullPath[128];

    char pktName[256];


    if (c->links[n].echoMailFlavour == normal)
        strcpy(flavourSuffix, "flo");
    else
        return 2;
	 
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
                if (c->links[n].hisAka.point != 0)
                    printf(" + %d:%d/%d.%d\t\tEchomail\n", c->links[n].hisAka.zone,
                                                           c->links[n].hisAka.net,
                                                           c->links[n].hisAka.node,
                                                           c->links[n].hisAka.point);
                else
                    printf(" + %d:%d/%d\t\tEchomail\n", c->links[n].hisAka.zone,
                                                           c->links[n].hisAka.net,
                                                           c->links[n].hisAka.node);


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
            if (c->links[n].hisAka.point != 0)
                printf(" + %d:%d/%d.%d\t\tNetmail\n", c->links[n].hisAka.zone,
                                                      c->links[n].hisAka.net,
                                                      c->links[n].hisAka.node,
                                                      c->links[n].hisAka.point);
            else
                printf(" + %d:%d/%d\t\tNetmail\n", c->links[n].hisAka.zone,
                                                      c->links[n].hisAka.net,
                                                      c->links[n].hisAka.node);
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
        /* and doesn't have hold */
        if ((c->links[i].email) && (c->links[i].echoMailFlavour != hold)) {
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

    printf("pkt-to-mail v0.1\n");

    if ((config = readConfig()) == NULL) {

        /* TODO: write logs */
    
        printf(" * Error reading config file! Aborting... \n");
        return -1;
    }

    error = send(config);

    switch (error) {
        case 1:
            printf(" - Error processing echomail.\n");
        break;
        case 2:
            printf(" - Error processing netmail.\n");
        break;
        
    }

    return error;
    
}


