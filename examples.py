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
