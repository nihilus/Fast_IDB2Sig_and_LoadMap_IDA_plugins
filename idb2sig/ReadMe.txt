/*************************************************************************
    IDB2SIG plugin
    Rewrite and add some abilyties by TQN (truong_quoc_ngan@yahoo.com)
    Reuse some code from IDB2PAT of J.C. Roberts <mercury@abac.com>

    Original written by Quine (quine@blacksun.res.cmu.edu) and Darko
    Visit Quine's IDA Page at http://surf.to/quine_ida

    Contribute to ExeTools and Woodmann forum and community
**************************************************************************
Revision History :
Version   Author    Date       Description
  V1.0    Quine    ??????????  creation.
  V1.1    Darko    04.10.2002  modification for IDA Pro v4.3 and SDK 4.3.
  V1.2    Darko    05.10.2002  pat file opened in appending mode.
  V1.3    Darko    21.12.2002  bug fix for reference bad address.
  V1.4    TQN      30.08.2004  bug fix for reference bad address.
                               some code optimize.
                               add options dialog.
                               add save and restore options to and from INI file.
                               Compile for IDA Pro v4.5.
*************************************************************************/

DEFAULT idb2sig.plw IN THIS PACKAGE IS FOR IDA 4.5!
If you want to use it with some other version of IDA you have to recompile it.

a) Copy idb2sig.plw and idb2sig.ini into IDA's plugin directory.
b) Press Shift key when click the plugin in Edit/Plugins menu of IDA will show
   the Options dialog. All options will be saved to INI file and will be reloaded
   when plugin loaded. All options have mouse hint. Take sometime to play with them.
c) Default shortcut key is: Ctrl-F7
