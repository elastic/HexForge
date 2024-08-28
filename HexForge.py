import idaapi
import inspect

from hexforge_modules import crypto, encoding, misc


CRYPTO_MODULE_PATH = "HexForge/crypto/"
ENCODING_MODULE_PATH = "HexForge/encoding/"
MISC_MODULE_PATH = "HexForge/misc/"

g_crypto_modules = [cls() for _, cls in inspect.getmembers(crypto, inspect.isclass)]
g_encoding_modules = [cls() for _, cls in inspect.getmembers(encoding, inspect.isclass)]
g_misc_modules = [cls() for _, cls in inspect.getmembers(misc, inspect.isclass)]


class hexforge_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = ""
    help = ""
    wanted_name = "HexForge"

    def init(self):
        idaapi.msg("init() called!\n")
        self._init_actions()
        self._init_hooks()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.msg("run() called with %d!\n" % arg)

    def term(self):
        self._del_action()
        idaapi.msg("term() called!\n")

    # --------------------------------------------------------------------------
    # Initializations
    # --------------------------------------------------------------------------

    def _init_actions(self) -> None:
        for module in g_crypto_modules + g_encoding_modules + g_misc_modules:
            module.init_action()

    def _del_action(self) -> None:
        for module in g_crypto_modules + g_encoding_modules + g_misc_modules:
            module.del_action()

    # --------------------------------------------------------------------------
    # Initialize Hooks
    # --------------------------------------------------------------------------

    def _init_hooks(self) -> None:
        """
        Install plugin hooks into IDA.
        """
        self._hooks = Hooks()
        self._hooks.hook()


# Plugin Hooks


class Hooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        """
        A right click menu is about to be shown. (IDA 7)
        """
        inject_actions(widget, popup, idaapi.get_widget_type(widget))
        return 0


# Prefix Wrappers


def inject_actions(form, popup, form_type) -> int:
    """
    Inject actions to popup menu(s) based on context.
    """

    if (form_type == idaapi.BWN_DISASMS) or (form_type == idaapi.BWN_DUMP):
        for module in g_crypto_modules:
            idaapi.attach_action_to_popup(
                form,
                popup,
                module.ACTION_NAME,
                CRYPTO_MODULE_PATH,
                idaapi.SETMENU_APP,
            )

        for module in g_misc_modules:
            idaapi.attach_action_to_popup(
                form,
                popup,
                module.ACTION_NAME,
                MISC_MODULE_PATH,
                idaapi.SETMENU_APP,
            )

        for module in g_encoding_modules:
            idaapi.attach_action_to_popup(
                form,
                popup,
                module.ACTION_NAME,
                ENCODING_MODULE_PATH,
                idaapi.SETMENU_APP,
            )

    return 0


# Register IDA plugin
def PLUGIN_ENTRY() -> hexforge_plugin_t:
    return hexforge_plugin_t()


PLUGIN_ENTRY()
