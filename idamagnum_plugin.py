import json

try:
    # Python2
    from urllib2 import urlopen
except ImportError:
    # Python3
    from urllib.request import urlopen

import idc
import idaapi
import idautils
from idaapi import plugin_t


try:
    # ida < 7.4
    from idaapi import Choose2 as Choose
    from idc import OpEnumEx as op_enum
except ImportError:
    # ida 7.4
    from ida_kernwin import Choose
    from idc import op_enum



class ChooseMagicNumber(Choose):
    
    def __init__(self,value,results):

        Choose.__init__(self,
            "[IdaMagnum] Select enum from MagnumDB.com for value : 0x%X" % value,
            [ ["name",   13 | Choose.CHCOL_PLAIN], 
              ["value",  10 | Choose.CHCOL_HEX],
              ["source",  13 | Choose.CHCOL_PLAIN],
            ],
            Choose.CH_MODAL
        )

        self._results = results

    def OnSelectLine(self, n):
        pass

    def OnGetLine(self, n):
        res = self._results[n]
        return [
            res["Title"], 
            res.get("HexValue", ""),
            res["DisplayFilePath"]
        ]  

    def OnRefresh(self, n):
        return n

    def OnGetSize(self):
        return len(self._results)

class SearchMagicNumber(idaapi.action_handler_t):

    MAGNUMDB_QUERY = "https://www.magnumdb.com/api.aspx?q=0x{value:X}&key={key:s}"
    MAGNUMDB_KEY = "f344dc86-7796-499f-be38-ec39a5414289"

    def __init__(self, manager):
        idaapi.action_handler_t.__init__(self)
        self._manager = manager

    def shift_bit_length(self, x):
        # https://stackoverflow.com/questions/14267555/find-the-smallest-power-of-2-greater-than-n-in-python
        return 1<<(x-1).bit_length()

    def activate(self, ctx):
        # print("ctx.cur_ea : 0x%x" % ctx.cur_ea)
        # print("ctx.cur_extracted_ea : 0x%x" % ctx.cur_extracted_ea)

        # Extract selected enum
        instruction = idc.GetDisasm(ctx.cur_ea)
        selection = ctx.cur_extracted_ea

        # correctly parse the selected value as int (hex or decimal)
        # since ctx.cur_extracted_ea has a bug (IDA always consider
        # the selected value as hex)
        if instruction.find("{0:X}h".format(selection)) != -1:
            # print("hex value found !")
            selected_value = ctx.cur_extracted_ea
        elif instruction.find("{0:d}".format(selection)) != -1:
            # print("int value found !")
            selected_value = int("%x" % ctx.cur_extracted_ea)
        else:
            # print("nothing selected !")
            return 1

        # next power of two for masking
        selected_value_mask = self.shift_bit_length(selected_value) - 1
        # print("selected_value : 0x%X" % selected_value)
        # print("selected_value mask : 0x%X" % selected_value_mask)

        # query magnum db
        url = SearchMagicNumber.MAGNUMDB_QUERY.format(
            value = selected_value,
            key = SearchMagicNumber.MAGNUMDB_KEY
        )
        answer = urlopen(url)
        results = json.loads(answer.read())
        
        # Let the user select the best answer
        c = ChooseMagicNumber(selected_value, results["Items"])
        selected_index = c.Show(modal=True)
        if selected_index < 0:
            return

        # Apply the newly found enum
        selected_item = results["Items"][selected_index]
        selected_name = selected_item["Title"].encode('ascii')
        selected_value = int(selected_item["Value"])

        # serial is important since several entries can have the same value
        entryid, serial = self._manager.add_magnumdb_entry(
            selected_name, 
            selected_value
        )

        # locate the operand where to apply the enum
        insn = idautils.DecodeInstruction(ctx.cur_ea)
        
        try:
            # ida < 7.4
            operands = insn.Operands
        except AttributeError:
            # ida 7.4
            operands = insn.ops

        for op in filter(lambda o: o.type == idaapi.o_imm,operands):

            # heuristic : the selected immediate is the first in the instruction with 
            # the same exact value (we are using a mask since IDA loves to set FFFFFFFF to high words)
            if op.value & selected_value_mask == selected_value:
                # Apply the enum
                op_enum(ctx.cur_ea, op.n, idaapi.get_enum("_IDA_MAGNUMDB"), serial)
                break

        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

class ConfigureIdaMagnum(idaapi.action_handler_t):
    def __init__(self, manager):
        idaapi.action_handler_t.__init__(self)
        self._manager = manager

    def activate(self, ctx):
         #self._manager.proc_rop()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS 

class IdaMagnumManager(object):

    def __init__(self):
        self._attach_to_menu_items()

    def _attach_to_menu_items(self):

        self.search_magic_desc = idaapi.action_desc_t(
            'idamagnum:searchmagic',             
            'search magic number ...',              
            SearchMagicNumber(self),         
            "Shift+M",                     
            'Search this value on MagnumDB', 
        )

        self.configure_plugin_desc = idaapi.action_desc_t(
            'idamagnum:configure',             
            'Configure',              
            ConfigureIdaMagnum(self),         
            "",                     
            'Configure plugin',
        )

        idaapi.register_action(self.search_magic_desc)
        idaapi.register_action(self.configure_plugin_desc)

        idaapi.attach_action_to_menu(
            'Edit/Plugins/IdaMagnum/',
            'idamagnum:searchmagic',
            idaapi.SETMENU_APP
        )

        idaapi.attach_action_to_menu(
            'Edit/Plugins/IdaMagnum/',
            'idamagnum:configure',
            idaapi.SETMENU_APP
        )

        return 0

    def _detach_from_menu_items(self):
        idaapi.detach_action_from_menu('Edit/Plugins/IdaMagnum/', 'idamagnum:searchmagic')
        idaapi.detach_action_from_menu('Edit/Plugins/IdaMagnum/', 'idamagnum:configure')

    def ensure_magnumdb_enum_type(self):
        """Ensure we have a valid MAGNUMDB enum"""

        enum_id = idaapi.get_enum("_IDA_MAGNUMDB")
        if enum_id == 0xffffffffffffffff:
            enum_id = idaapi.add_enum(idaapi.BADADDR, "_IDA_MAGNUMDB", 0)

        return enum_id

    def add_magnumdb_entry(self, name, value):
         
        enum_id = self.ensure_magnumdb_enum_type()

        # idaapi.add_enum_member accept only str (Py3)
        if type(name) == type(b''):
            name = name.decode('utf-8')

        serial = 0
        enum_memberid = idaapi.get_enum_member(enum_id, value, serial, 0)
        while  enum_memberid != 0xffffffffffffffff:

            if idaapi.get_enum_member_name(enum_memberid) == name:
                return enum_memberid, serial

            serial += 1
            enum_memberid = idaapi.get_enum_member(enum_id, value, serial, 0)

        if enum_memberid == 0xffffffffffffffff:
            enum_memberid = idaapi.add_enum_member(enum_id, name, value)

        return enum_memberid, serial
        

class IdaMagnumPlugin(plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "search magic numbers using magnumdb.com"
    help = "search magic numbers using magnumdb.com"
    wanted_name = "IdaMagnum"
    wanted_hotkey = ""


    def init(self):
        global ida_magnumdb_manager

        if not 'ida_magnumdb_manager' in globals():
            ida_magnumdb_manager = IdaMagnumManager()

            print("[IdaMagnum] Ida plugin for MagnumDB v0.0 initialized")

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        pass

def PLUGIN_ENTRY():
    return IdaMagnumPlugin()