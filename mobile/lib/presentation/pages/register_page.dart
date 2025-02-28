import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:todo_mobile/domain/entities/user_entity.dart';
import 'package:todo_mobile/presentation/bloc/user_bloc.dart';
import 'package:todo_mobile/presentation/bloc/user_event.dart';

class RegisterPage extends StatefulWidget {
  const RegisterPage({super.key});

  @override
  State<RegisterPage> createState() => _RegisterPageState();
}

class _RegisterPageState extends State<RegisterPage> {
  final _nameController = TextEditingController();
  final _emailController = TextEditingController();
  final _passwordController = TextEditingController();

  @override
  void dispose() {
    _nameController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  void _submitForm(BuildContext context) {
    final name = _nameController.text.trim();
    final email = _emailController.text.trim();
    final password = _passwordController.text.trim();

    if (name.isEmpty || email.isEmpty || password.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please fill in all fields')),
      );
      return;
    }

    // Dispatch an event to create a new todo
    context.read<UserBloc>().add(
          UserRegisterEvent(
              UserRegisterEntity(name: name, email: email, password: password)),
        );

    // Navigate back after creating the todo
    Navigator.of(context).pop();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        centerTitle: true,
        title: Text("Register"),
      ),
      body: Padding(
        padding: EdgeInsets.all(10),
        child: Column(
          children: [
            TextField(
              controller: _nameController,
              decoration: const InputDecoration(labelText: "Name"),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: _emailController,
              decoration: const InputDecoration(labelText: "Email"),
            ),
            const SizedBox(height: 10),
            TextField(
              controller: _passwordController,
              decoration: const InputDecoration(labelText: "Password"),
            ),
            const SizedBox(height: 10),
            ElevatedButton(
                onPressed: () => _submitForm(context),
                child: const Text("Register"))
          ],
        ),
      ),
    );
  }
}
