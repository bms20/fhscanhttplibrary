
#ifndef __HTML_PARSER__H__
#define __HTML_PARSER__H__

#if HAVE_STDBOOL_H
# include <stdbool.h>
#else
# if ! HAVE__BOOL
#  ifdef __cplusplus
typedef bool _Bool;
#  else
typedef unsigned HTTPCHAR _Bool;
#  endif
# endif
# define bool _Bool
# define false 0
# define true 1
# define __bool_true_false_are_defined 1
#endif

//defines from wget.h

/* The number of elements in an array.  For example:
static char a[] = "foo";     -- countof(a) == 4 (note terminating \0)
int a[5] = {1, 2};           -- countof(a) == 5
char *a[] = {                -- countof(a) == 3
"foo", "bar", "baz"
}; */
#define countof(array) (sizeof (array) / sizeof ((array)[0]))
/* Convert an ASCII hex digit to the corresponding number between 0
and 15.  H should be a hexadecimal digit that satisfies isxdigit;
otherwise, the result is undefined.  */
#define XDIGIT_TO_NUM(h) ((h) < 'A' ? (h) - '0' : TOUPPER (h) - 'A' + 10)


#define STANDALONE
/* HTML parser for Wget.
Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
2007, 2008 Free Software Foundation, Inc.

This file is part of GNU Wget.

GNU Wget is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or (at
your option) any later version.

GNU Wget is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Wget.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this program, or any covered work, by linking or
combining it with the OpenSSL project's OpenSSL library (or a
modified version of that library), containing parts covered by the
terms of the OpenSSL or SSLeay licenses, the Free Software Foundation
grants you additional permission to convey the resulting work.
Corresponding Source for a non-source form of such a combination
shall include the source code for the parts of OpenSSL used as well
as that of the covered work.  */

/* The only entry point to this module is map_html_tags(), which see.  */

/* TODO:

- Allow hooks for callers to process contents outside tags.  This
is needed to implement handling <style> and <script>.  The
taginfo structure already carries the information about where the
tags are, but this is not enough, because one would also want to
skip the comments.  (The funny thing is that for <style> and
<script> you *don't* want to skip comments!)

- Create a test suite for regression testing. */

/* HISTORY:

This is the third HTML parser written for Wget.  The first one was
written some time during the Geturl 1.0 beta cycle, and was very
inefficient and buggy.  It also contained some very complex code to
remember a list of parser states, because it was supposed to be
reentrant.

The second HTML parser was written for Wget 1.4 (the first version
by the name `Wget'), and was a complete rewrite.  Although the new
parser behaved much better and made no claims of reentrancy, it
still shared many of the fundamental flaws of the old version -- it
only regarded HTML in terms tag-attribute pairs, where the
attribute's value was a URL to be returned.  Any other property of
HTML, such as <base href=...>, or strange way to specify a URL,
such as <meta http-equiv=Refresh content="0; URL=..."> had to be
crudely hacked in -- and the caller had to be aware of these hacks.
Like its predecessor, this parser did not support HTML comments.

After Wget 1.5.1 was released, I set out to write a third HTML
parser.  The objectives of the new parser were to: (1) provide a
clean way to analyze HTML lexically, (2) separate interpretation of
the markup from the parsing process, (3) be as correct as possible,
e.g. correctly skipping comments and other SGML declarations, (4)
understand the most common errors in markup and skip them or be
relaxed towrds them, and (5) be reasonably efficient (no regexps,
minimum copying and minimum or no heap allocation).

I believe this parser meets all of the above goals.  It is
reasonably well structured, and could be relatively easily
separated from Wget and used elsewhere.  While some of its
intrinsic properties limit its value as a general-purpose HTML
parser, I believe that, with minimum modifications, it could serve
as a backend for one.

Due to time and other constraints, this parser was not integrated
into Wget until the version 1.7. */

/* DESCRIPTION:

The single entry point of this parser is map_html_tags(), which
works by calling a function you specify for each tag.  The function
gets called with the pointer to a structure describing the tag and
its attributes.  */

/* To test as standalone, compile with `-DSTANDALONE -I.'.  You'll
still need Wget headers to compile.  */


#ifdef STANDALONE
# undef xmalloc
# undef xrealloc
# undef xfree
# define xmalloc malloc
# define xrealloc realloc
# define xfree free

# undef ISSPACE
# undef ISDIGIT
# undef ISXDIGIT
# undef ISALPHA
# undef ISALNUM
# undef TOLOWER
# undef TOUPPER

# define ISSPACE(x) _istspace (x)
# define ISDIGIT(x) _istdigit (x)
# define ISXDIGIT(x) _istxdigit (x)
# define ISALPHA(x) _istalpha (x)
# define ISALNUM(x) _istalnum (x)
# define TOLOWER(x) _totlower (x)
# define TOUPPER(x) _totupper (x)

struct hash_table {
	int dummy;
};
#define hash_table_get(a,b) b
/*
static void *hash_table_get (const struct hash_table *ht, void *ptr)
{
	//printf("*** %s ***\n",ptr);
	return ptr;
}
*/
#endif






/*
Esta estructura contiene una lista de etiquetas susceptibles a tener enlaces HTTP.
*/

typedef struct {
	HTTPCHAR tagattribute[50];
	HTTPCHAR tagname[50];
} VALIDTAGS;

int IsValidHTMLTag(HTTPCHAR *tagattribute, HTTPCHAR *tagname);







/* Declarations for html-parse.c.
   Copyright (C) 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
   2007, 2008 Free Software Foundation, Inc.

This file is part of GNU Wget.

GNU Wget is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
 (at your option) any later version.

GNU Wget is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Wget.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this program, or any covered work, by linking or
combining it with the OpenSSL project's OpenSSL library (or a
modified version of that library), containing parts covered by the
terms of the OpenSSL or SSLeay licenses, the Free Software Foundation
grants you additional permission to convey the resulting work.
Corresponding Source for a non-source form of such a combination
shall include the source code for the parts of OpenSSL used as well
as that of the covered work.  */


struct attr_pair {
  HTTPCHAR *name;			/* attribute name */
  HTTPCHAR *value;			/* attribute value */

  /* Needed for URL conversion; the places where the value begins and
     ends, including the quotes and everything. */
  HTTPCSTR value_raw_beginning;
  int value_raw_size;

  /* Used internally by map_html_tags. */
  int name_pool_index, value_pool_index;
};

struct taginfo {
  HTTPCHAR *name;			/* tag name */
  int end_tag_p;		/* whether this is an end-tag */
  int nattrs;			/* number of attributes */
  struct attr_pair *attrs;	/* attributes */

  HTTPCSTR start_position;	/* start position of tag */
  HTTPCSTR end_position;	/* end position of tag */
};

struct hash_table;		/* forward declaration */

/* Flags for map_html_tags: */
#define MHT_STRICT_COMMENTS  1  /* use strict comment interpretation */
#define MHT_TRIM_VALUES      2  /* trim attribute values, e.g. interpret
                                   <a href=" foo "> as "foo" */

void map_html_tags (HTTPCSTR , int,
		    void (*) (struct taginfo *, void *, HTTPCHAR*, HTTPCHAR*,struct httpdata*),
			void *, int,
		    const struct hash_table *, const struct hash_table *,
			HTTPCHAR *, HTTPCHAR *,httpdata*);

void doSpider(HTTPCHAR *host, HTTPCHAR* url,HTTPCHAR *x, int length,int ssl);

#endif /* __HTML_PARSER__H__ */


