Fast_IDB2Sig_and_LoadMap_IDA_plugins
====================================
http://www.woodmann.com/collaborative/tools/index.php/Fast_IDB2Sig_and_LoadMap_IDA_plugins

It took me two weeks to write two IDA plugins, a renew, fast IDB2Sig plugin and a new, very fast LoadMap plugin.
The IDB2SIG plugin I rewrote base on the orginal source code and idea of:
- Quine (quine@blacksun.res.cmu.edu)
- Darko
- IDB2PAT of J.C. Roberts <mercury@abac.com>
Thanks all of you very much. I think all of you will allow me to public the new source code.
The LoadMap plugin I wrote base on the idea of Toshiyuki Tega. It will supports loading and parsing VC++, Borland (Delphi/BC++/CBuilder) and DeDe map files.
And with two plugins, I need only two days to create two signature file for Delphi 6/7. Very fast and convenience. Hereafter, we can use two above plugins to create signature files, load map symbols...

Source is included, and plugins are precompiled for IDA 4.5 and 5.2.

---- UPDATED by Swine
06.10.2011 Fixed behavior for 64-bit disassemblies
