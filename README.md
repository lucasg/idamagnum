# idamagnum
idamagnum is a plugin for integrating MagnumDB requests within IDA

## Installation

Just drop the single Python file `idamagnum_plugin.py` into IDA's `plugin` directory.

## Usage

Type `Shift-M` when selecting an unknown constants, and a chooser menu should pop up (kinda like `M` shortcut) populated with values from MagnumDB. Once the enum selected, the plugin automatically tag the constant with the correct name.

## Credits

[Simon Mourier](https://twitter.com/smourier)  for creating MagnumDB.com and helping me quering it from IDA.
