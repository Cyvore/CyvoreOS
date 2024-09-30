"""this doesn't need to be here, but you will need winreg."""

import winreg

def define_action_on(filetype, registry_title, command, title=None):
    """
    define_action_on(filetype, registry_title, command, title=None)
        filetype:   either an extension type (ex. ".txt") or one of the special values ("*" or "Directory"). 
                    Note that "*" is files only--if you'd like everything to have your action, 
                    it must be defined under "*" and "Directory"
        registry_title: the title of the subkey, not important, but probably ought to be relevant. 
                        If title=None, this is the text that will show up in the context menu.
    """
    # all these opens/creates might not be the most efficient way to do it,
    # but it was the best I could do safely, without assuming any keys were defined.
    reg = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, "Software\\Classes", 0, winreg.KEY_SET_VALUE
    )

    k1 = winreg.CreateKey(
        reg, filetype
    )  # handily, this won't delete a key if it's already there.
    k2 = winreg.CreateKey(k1, "shell")
    k3 = winreg.CreateKey(k2, registry_title)
    k4 = winreg.CreateKey(k3, "command")

    if title is not None:
        winreg.SetValueEx(k3, None, 0, winreg.REG_SZ, title)

    winreg.SetValueEx(k4, None, 0, winreg.REG_SZ, command)
    winreg.CloseKey(k3)
    winreg.CloseKey(k2)
    winreg.CloseKey(k1)
    winreg.CloseKey(reg)
