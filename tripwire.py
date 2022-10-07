from collections import OrderedDict
import types

def record_access_tree_dict(d, accessed_path, path_separator='.'):
    node = d
    path_parts = accessed_path.split(path_separator, 1)
    key = path_parts[0]
    path_tail = path_parts[1] if len(path_parts) > 1 else None
    while key:
        if key in node:
            if type(node[key]) is dict:
                node = node[key]
            elif node[key] == True and path_tail:
                node[key] = {}
                node = node[key]
        else:
            node[key] = True
            node = node[key]
        if not path_tail:
            key = None
        else:
            key_parts = path_tail.split('.', 1)
            key = key_parts[0]
            path_tail = key_parts[1] if len(key_parts) > 1 else None
    return d


tripwired_obj_special_attr_names = set([
    # private attributes
    '__tripwire_parent__',
    '__tripwire_parent_attr_name__',
    # public attributes
    'tripwire_shadow',
    'tripwire_access_history',
])

def is_dunder(attr_name):
    return attr_name.startswith('__') and attr_name.endswith('__')

base_scalar_types = (type(None), bool, int, float, str)
base_collection_types = (tuple, set, list, dict, OrderedDict)

base_types = base_scalar_types + base_collection_types

TripwiredClasses = {}
TripwiredObjects = {}

def is_tripwired(obj):
    return id(obj) in TripwiredObjects

def record_tripwire_refs(obj, tripwired_obj):
    TripwiredObjects[id(obj)] = { 'original': obj }
    TripwiredObjects[id(tripwired_obj)] = {
        'original': obj,
        'tripwired': tripwired_obj,
    }

def to_original(obj):
    original_object = TripwiredObjects[id(obj)]['original']
    return original_object

def get_or_create_tripwired(obj, parent_object=None, parent_attr_name=None):
    if id(obj) not in TripwiredObjects:
        return tripwire(obj, parent_object=parent_object, parent_attr_name=parent_attr_name)
    else:
        return TripwiredObjects[id(obj)]['tripwired']

APPEND_TRIPWIRE_ACCESS_RECORD_MAX_RECURSION = 100
def append_tripwire_access_record(tripwired_obj, path, call_args=None, kwargs=None, separator='.', depth=0):
    if depth > APPEND_TRIPWIRE_ACCESS_RECORD_MAX_RECURSION:
        raise Exception('recursion exceeded on `append_tripwire_access_record()`')
    tripwired_obj.tripwire_access_history.append((path, call_args, kwargs))
    record_access_tree_dict(tripwired_obj.tripwire_shadow, path, path_separator=separator)
    if tripwired_obj.__tripwire_parent__ is not None:
        nested_access_key = f'{tripwired_obj.__tripwire_parent_attr_name__}{separator}{path}'
        append_tripwire_access_record(tripwired_obj.__tripwire_parent__, nested_access_key, separator=separator, depth=depth+1)

def wrap_obj_type_method(obj_type, method_name, wrapping_obj_type):
    method = getattr(obj_type, method_name)
    def wrapped_method(self, *args, **kwargs):
        original_object = to_original(self)
        result = method(original_object, *args, **kwargs)
        if method_name not in tripwired_obj_special_attr_names:
            append_tripwire_access_record(self, method_name, call_args=args, kwargs=kwargs)
        return result
    wrapped_method.__name__ = f'wrapped__{method_name}'
    wrapped_method.__qualname__ = f'{wrapping_obj_type.__qualname__}.{wrapped_method.__name__}'
    return wrapped_method

def tripwire(obj, parent_object=None, parent_attr_name=None): #, parent_key=None):
    obj_type = type(obj)

    tripwired_obj_typename = f'Tripwired__{type(obj).__qualname__}'
    if tripwired_obj_typename in TripwiredClasses:
        tripwired_obj_type = TripwiredClasses[tripwired_obj_typename]
        tripwired_obj_type_created = False
    else:
        base_type = obj_type if obj_type in base_types else object
        tripwired_obj_type = types.new_class(tripwired_obj_typename, (base_type,))
        TripwiredClasses[tripwired_obj_typename] = tripwired_obj_type
        tripwired_obj_type_created = True
    tripwired_obj = tripwired_obj_type()

    setattr(tripwired_obj, '__tripwire_parent__', parent_object)
    setattr(tripwired_obj, '__tripwire_parent_attr_name__', parent_attr_name)
    setattr(tripwired_obj, 'tripwire_shadow', {})
    setattr(tripwired_obj, 'tripwire_access_history', [])

    if tripwired_obj_type_created:
        wrapped_methods = {}
        for attr_name in dir(obj_type):
            if attr_name not in ('__class__', '__class_getitem__', '__class_setitem__', '__subclasshook__', '__init__', '__init_subclass__', '__new__', '__getitem__', '__getattribute__', '__setattr__'):
                attr = getattr(obj_type, attr_name)
                if callable(attr):
                    wrapped_method = wrap_obj_type_method(obj_type, attr_name, tripwired_obj_type)
                    wrapped_methods[attr_name] = wrapped_method
                    setattr(tripwired_obj_type, attr_name, wrapped_method)

        if hasattr(obj_type, '__getitem__'):
            __obj_getitem__ = obj_type.__getitem__
            def __tripwired_getitem__(tripwired_obj, key):
                original_obj = to_original(tripwired_obj)
                value = __obj_getitem__(original_obj, key)
                if not callable(value):
                    _value = value
                    value = tripwire(_value, parent_object=tripwired_obj, parent_attr_name=key)
                append_tripwire_access_record(tripwired_obj, key)
                return value
            tripwired_obj_type.__getitem__ = __tripwired_getitem__

        __obj_getattribute__ = obj_type.__getattribute__
        __default_getattribute__ = tripwired_obj_type.__getattribute__
        def __tripwired_getattribute__(tripwired_obj, attr_name):
            if attr_name in tripwired_obj_special_attr_names:
                return __default_getattribute__(tripwired_obj, attr_name)
            if attr_name in wrapped_methods:
                append_tripwire_access_record(tripwired_obj, attr_name)
                return __default_getattribute__(tripwired_obj, attr_name)
            original_obj = to_original(tripwired_obj)
            value = __obj_getattribute__(original_obj, attr_name)
            if not callable(value):
                value = tripwire(value, parent_object=tripwired_obj, parent_attr_name=attr_name)
            append_tripwire_access_record(tripwired_obj, attr_name)
            return value
        tripwired_obj_type.__getattribute__ = __tripwired_getattribute__
    record_tripwire_refs(obj, tripwired_obj)
    return tripwired_obj
