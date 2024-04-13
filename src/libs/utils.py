from dataclasses import MISSING, asdict, fields, is_dataclass
from typing import Any, Dict, Iterable, List, Mapping, Type, Union, get_type_hints


def to_dict(obj: Any) -> Union[Dict[str, Any], List[Any], Any]:
    """
    Рекурсивно преобразует объекты, включая датаклассы и NamedTuple, в словари или списки для сериализации.
    
    Поддерживает вложенные датаклассы, NamedTuple, словари, списки и базовые типы данных.
    
    Args:
        obj: Преобразуемый объект. Может быть датаклассом, NamedTuple, словарём, списком, 
             итерируемым объектом или базовым типом данных.
    
    Returns:
        Union[Dict[str, Any], List[Any], Any]: Словарь или список, представляющий исходный объект,
                                               или исходный объект, если он не требует преобразования.
    """
    # Проверяем, является ли объект датаклассом.
    if is_dataclass(obj):
        # Преобразовываем датакласс в словарь, рекурсивно вызывая to_dict для каждого значения.
        return {k: to_dict(v) for k, v in asdict(obj).items()}
    # Проверяем, является ли объект NamedTuple.
    elif isinstance(obj, tuple) and hasattr(obj, '_fields'):
        # Преобразовываем NamedTuple в словарь, используя _fields для ключей.
        return {k: to_dict(v) for k, v in zip(getattr(obj, '_fields'), obj)}
    # Проверяем, является ли объект Mapping (например, словарём).
    elif isinstance(obj, Mapping):
        # Преобразовываем Mapping в словарь, рекурсивно вызывая to_dict для каждого значения.
        return {k: to_dict(v) for k, v in obj.items()}
    # Проверяем, является ли объект Iterable (но не строкой), например, списком или множеством.
    elif isinstance(obj, Iterable) and not isinstance(obj, str):
        # Преобразовываем Iterable в список, рекурсивно вызывая to_dict для каждого элемента.
        return [to_dict(v) for v in obj]
    # Возвращаем объект без изменений, если он не подходит ни под одну из предыдущих категорий.
    else:
        return obj
    
def from_dict(obj_type: Type[Any], obj_dict: Dict[str, Any]) -> Any:
    """
    Преобразует словарь в объект указанного типа. Работает с датаклассами, NamedTuple и базовыми типами данных.
    
    Args:
        obj_type: Тип возвращаемого объекта. Может быть датаклассом, NamedTuple или другим типом данных.
        obj_dict: Словарь с данными для преобразования в объект.
    
    Returns:
        Объект указанного типа, сконструированный из словаря.
    """
    # Если obj_dict не является словарём, это базовый тип данных, и его можно возвращать напрямую.
    if not isinstance(obj_dict, dict):
        return obj_dict
    
    # Обработка датаклассов
    if is_dataclass(obj_type):
        field_types = get_type_hints(obj_type)
        field_defaults = {f.name: f.default for f in fields(obj_type) if f.default is not MISSING}
        constructed_fields = {}
        for f in field_types:
            if f in obj_dict or f in field_defaults:
                field_value = obj_dict.get(f, field_defaults.get(f))
                constructed_fields[f] = from_dict(field_types[f], field_value)
        return obj_type(**constructed_fields)
    
    # Обработка NamedTuple
    elif isinstance(obj_type, type) and issubclass(obj_type, tuple) and hasattr(obj_type, '_fields'):
        field_types = get_type_hints(obj_type)
        return obj_type(**{f: from_dict(field_types[f], obj_dict.get(f, None)) for f in getattr(obj_type, '_fields')})
    
    # Возвращаем словарь, если тип не является ни датаклассом, ни NamedTuple
    else:
        return obj_dict