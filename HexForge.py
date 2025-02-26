import idaapi
import inspect

from hexforge_modules import crypto_modules, encoding_modules, misc_modules, search_modules
from hexforge_modules.search_modules import SearchVirustotalBytes, SearchVirustotalString, SearchGitHub, SearchGoogle, SearchGrepApp

CRYPTO_MODULE_PATH = "HexForge/crypto/"
ENCODING_MODULE_PATH = "HexForge/encoding/"
MISC_MODULE_PATH = "HexForge/misc/"
SEARCH_MODULE_PATH = "HexForge/search/"


ida_version = idaapi.get_kernel_version()
is_ida_9_or_later = float(ida_version) >= 9.0

g_crypto_modules = []
g_encoding_modules = []
g_misc_modules = []
g_search_modules = []

class hexforge_plugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = ""
    help = ""
    wanted_name = "HexForge"

    def init(self):
        global g_crypto_modules
        global g_encoding_modules
        global g_misc_modules
        global g_search_modules

        idaapi.msg("init() called!\n")
        g_crypto_modules = self._init_modules(crypto_modules)
        g_encoding_modules = self._init_modules(encoding_modules)
        g_misc_modules = self._init_modules(misc_modules)
        g_search_modules = self._init_modules(search_modules)
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
    def _init_modules(self, modules) -> None:
        initialized_modules = []
        for _, cls in inspect.getmembers(modules, inspect.isclass):
            try:
                initialized_modules.append(cls())
            except Exception as e:
                idaapi.msg(f"Failed to initialize {cls.__name__}: {e}\n")
        return initialized_modules

    def _init_actions(self) -> None:
        for module in g_crypto_modules + g_encoding_modules + g_misc_modules + g_search_modules:
            module.init_action()

    def _del_action(self) -> None:
        for module in g_crypto_modules + g_encoding_modules + g_misc_modules + g_search_modules:
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

    if is_ida_9_or_later:
        valid_form_types = (idaapi.BWN_DISASM, idaapi.BWN_HEXVIEW, idaapi.BWN_PSEUDOCODE)
    else:
        valid_form_types = (idaapi.BWN_DISASMS, idaapi.BWN_DUMP, idaapi.BWN_PSEUDOCODE)

    if form_type in valid_form_types:
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

        for module in g_search_modules:
            # Exclude byte searches in decompiler
            if form_type == idaapi.BWN_PSEUDOCODE and isinstance(module, SearchVirustotalBytes):
                continue
            
            # Exclude string searches in disassembler
            if is_ida_9_or_later:
                if form_type == idaapi.BWN_DISASM and isinstance(module, (SearchGoogle, SearchGrepApp,SearchGitHub,SearchVirustotalString)):
                    continue
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    module.ACTION_NAME,
                    SEARCH_MODULE_PATH,
                    idaapi.SETMENU_APP,
                )

            else:
                if form_type == idaapi.BWN_DISASMS and isinstance(module, (SearchGoogle, SearchGrepApp,SearchGitHub,SearchVirustotalString)):
                    continue
                idaapi.attach_action_to_popup(
                    form,
                    popup,
                    module.ACTION_NAME,
                    SEARCH_MODULE_PATH,
                    idaapi.SETMENU_APP,
                )

    return 0


# Register IDA plugin
def PLUGIN_ENTRY() -> hexforge_plugin_t:
    return hexforge_plugin_t()


PLUGIN_ENTRY()
