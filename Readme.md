Oxen
====

What is this
------------
Oxygen Enterprise (oxygencloud.com) doesn't correct errors very well. This uses the Oxygen REST API to check your local dir against the remote, e.g. it will tell you if there are differences between what is synced on your hard drive with what is on the servers.

What Do I need
--------------
- An Oxygen API key. An Oxygen Admin can ask for one of these. Drop these in a .api file in the current directory, in a text file in form:
>KEY:somekeyhere019i234123341
>SECRET:somesecrethere98209820982098
- An Oxygen API username/password. You set this for your username via My Applications in the Oxygen webministration page. Drop it in a plain text file in the form:
>id:youruserid@youraddress.example.com
>password:yourpasswordhere
- This is in Python 3. Use Python 3.
- Some python modules. Specifically hmac is the most obscure one. Check out the requirements.txt file.

This was also whipped up on a WINDOWS box. So beware windows-isms.

How Do I use it
---------------
Running it will go through your spaces, directories, then files and error to screen if there are discrepancies.

Discrepancy types:
- Files exist locally, but aren't on server
- Files exist remotely, but aren't here locally
- Files exist on both, but timestamps don't line up
- Files exist on both, but filesizes don't line up

Running it with -f or --fix will attempt to fix things when remote files are missing. But this won't help if "~$blah.docx" and "*.tmp" files are the ones missing, since Oxygen ignores these. Only use after a non -f dry run I guess.

Potentially a -f type fix might work with timestamp/filesize issues, but there is a danger here of overwriting good commits and I ran out of time to think about it.

Running it with --verbose will show you that it's actually doing something.

Running it with --debug tells all.

There is a setup.py file -- run as python setup.py build2exe if you want to generate a windows dist/ and executable.

Don't sue me because
--------------------
This is a quick hack. I don't even have test suites on it. I started turning it into a class but finished employment where I needed it and didn't get to revisit it.

If you run it with -f, it should only fix up directories and won't really overwrite anything, but it will try upload a .paulnguyenfix file to trigger some changes if the remote is missing files.

Copyright
---------
2015 - Paul Nguyen
