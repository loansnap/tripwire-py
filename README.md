# Tripwire

## About

Tripwire is a debug utility to track object attributes access. Whenever you're in doubth about which particular attributes of your data are being used and accessed - just create a tripwired object and track the shadow.

Key design principles:
 - Tripwire creates a new object, that wrapps proxies all `__getattribure__` and `__getitem__` calls to a target object
 - Tripwire keeps records of relations between tripwired and original objects in `TripwiredObjects` closure dict. It keys off of object ids.
 - Any time you access any attributes or keys of a tripwired object, you will create a **new** tripwired object. This is needed to keep a proper track of nested child attribute access on the parent, as the childs can be accessed thru various routes.
 - This comes with an asterisk: if your child and parent have back and forth references - jumping between them will cause to create a "circular knot" in the attr access path. Just beware.
 - Tracker function ignores "dunder" methods like `__repr__`, `__len__`, `__str__`, etc.
 
## Examples

```python
from tripwire import tripwire

# Test examples

obj = {'a': 1, 'b': 2, 'c': 3, 'd': { 'a': 5, 'b': 6, 'c': 7}}
_obj = tripwire(obj)

_obj['a']
assert _obj.tripwire_shadow == {'a': True}
_obj['b']
assert _obj.tripwire_shadow == {'a': True, 'b': True}
_obj['d']
assert _obj.tripwire_shadow == {'a': True, 'b': True, 'd': True}
_obj['d']['a']
assert _obj.tripwire_shadow == {'a': True, 'b': True, 'd': {'a': True}}

class TestClass:
    attr_1 = 'hello'
    attr_2 = 'world'
    attr_3 = 123

class HigherOrderTestClass:
    attr_1 = 'I am higher order'
    attr_2 = TestClass()

data = HigherOrderTestClass()
_data = tripwire(data)
_data.attr_1
assert _data.tripwire_shadow == { 'attr_1': True }
_data.attr_2
assert _data.tripwire_shadow == { 'attr_1': True, 'attr_2': True }
_data.attr_2.attr_1
assert _data.tripwire_shadow == { 'attr_1': True, 'attr_2': { 'attr_1': True } }
_data.attr_2.attr_2
assert _data.tripwire_shadow == { 'attr_1': True, 'attr_2': { 'attr_1': True, 'attr_2': True } }

```
