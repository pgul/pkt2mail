/* --------------------------------------------------------------------------
 * PKT-TO-MAIL v0.2                                            Mar 23rd, 2000
 * --------------------------------------------------------------------------
 *
 *   This file is part of pkt2mail. The encoding algorithmn was designed by
 *   German Theler.
 * 
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
 *
 * --------------------------------------------------------------------------
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "mime.h"

int toBase64(FILE *inFile, FILE *outFile)
{
    int a, b, c, d;
    int x, y, z;
    int counter = 0;

    while ((x = getc(inFile)) != EOF) {
        if (counter >= 64) {
            fprintf(outFile, "\n");
            counter = 0;
        } else
            counter += 4;
            
        if ((y = getc(inFile)) == EOF) {
            a = x >> 2;
            b = x << 4 & 0x3F;
            putc(base64[a], outFile);
            putc(base64[b], outFile);
            putc('=', outFile);
            putc('=', outFile);

            fprintf(outFile, "\n");

            return 0;
        }

        if ((z = getc(inFile)) == EOF) {
            a = x >> 2;
            b = (x << 4 | y >> 4) & 0x3F;
            c = y << 2 & 0x3F;

            putc(base64[a], outFile);
            putc(base64[b], outFile);
            putc(base64[c], outFile);
            putc('=', outFile);

            fprintf(outFile, "\n");
            
            return 0;
        }

        a = x >> 2;
        b = (x << 4 | y >> 4) & 0x3F;
        c = (y << 2 | z >> 6) & 0x3F;
        d = z & 0x3F;

        putc(base64[a], outFile);
        putc(base64[b], outFile);
        putc(base64[c], outFile);
        putc(base64[d], outFile);
    }

    fprintf(outFile, "\n");
    return 0;
    
}

        
