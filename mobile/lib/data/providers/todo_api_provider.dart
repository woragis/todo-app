import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:todo_mobile/data/models/todo_model.dart';
import 'package:todo_mobile/data/models/todo_response_model.dart';

// class TodoApiProvider {
//   final String baseUrl;

//   TodoApiProvider({required this.baseUrl});

//   Future<List<TodoModel>> fetchTodos() async {
//     final uri = Uri.parse('$baseUrl/todos/');
//     final response = await http.get(uri);
//     if (response.statusCode == 200) {
//       TodosResponseModel data =
//           TodosResponseModel.fromJson(json.decode(response.body));
//       return data.data;
//     } else {
//       throw Exception('Failed to fetch todos');
//     }
//   }

//   Future<TodoModel> createTodo(NewTodo newTodo) async {
//     final uri = Uri.parse('$baseUrl/todos/');
//     final response = await http.post(
//       uri,
//       headers: {'Content-Type': 'application/json'},
//       body: json.encode(newTodo.toJson()),
//     );
//     if (response.statusCode == 201) {
//       return TodoModel.fromJson(json.decode(response.body).data);
//     } else {
//       throw Exception('Failed to create todo');
//     }
//   }

//   Future<void> deleteTodoById(String id) async {
//     final uri = Uri.parse('$baseUrl/todos/$id');
//     final response = await http.delete(uri);
//     if (response.statusCode != 200) {
//       throw Exception('Failed to delete todo');
//     }
//   }
// }

class TodoApiProvider {
  final String baseUrl;

  TodoApiProvider({required this.baseUrl});

  Future<List<TodoModel>> fetchTodos() async {
    final uri = Uri.parse('$baseUrl/todos/');
    final response = await http.get(uri);
    if (response.statusCode == 200) {
      final data = TodosResponseModel.fromJson(json.decode(response.body));
      return data.data;
    } else {
      throw Exception('Failed to fetch todos');
    }
  }

  Future<TodoModel> fetchTodoById(String id) async {
    final uri = Uri.parse('$baseUrl/todos/$id');
    final response = await http.get(uri);
    if (response.statusCode == 200) {
      return TodoModel.fromJson(json.decode(response.body).data);
    } else {
      throw Exception('Failed to fetch todo');
    }
  }

  Future<TodoModel> createTodo(NewTodoModel newTodo) async {
    final uri = Uri.parse('$baseUrl/todos/');
    final response = await http.post(
      uri,
      headers: {'Content-Type': 'application/json'},
      body: json.encode(newTodo.toJson()),
    );
    if (response.statusCode == 201) {
      return TodoModel.fromJson(json.decode(response.body)['data']);
    } else {
      throw Exception('Failed to create todo');
    }
  }

  Future<TodoModel> updateTodo(TodoModel todo) async {
    final uri = Uri.parse('$baseUrl/todos/${todo.id}');
    final response = await http.put(
      uri,
      headers: {'Content-Type': 'application/json'},
      body: json.encode(todo.toJson()),
    );
    if (response.statusCode == 200) {
      return TodoModel.fromJson(json.decode(response.body).data);
    } else {
      throw Exception('Failed to update todo');
    }
  }

  Future<void> deleteTodoById(String id) async {
    final uri = Uri.parse('$baseUrl/todos/$id');
    final response = await http.delete(uri);
    if (response.statusCode != 200) {
      throw Exception('Failed to delete todo');
    }
  }
}
