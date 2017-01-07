###########
Limitations
###########

As an abstraction library using other libraries, **gpgliblib** is limited by
what all other libraries have to offer. Therefore and for lack of resources,
this library only offers a very limited subset of GnuPG. In particular, key
handling has many limitations:

* No support for user IDs.
* No support for subkeys.
* No support for many interesting key properties (e.g. key length and algorithm, ...)
* No support for generating, exporting, deleting or uploading keys.

General limitations include:

* Only detached signatures can currently be created.

