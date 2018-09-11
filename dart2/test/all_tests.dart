library jwt.all_jwt.test;

import 'package:test/test.dart';

import 'jwa_test.dart' as jwa;
import 'jwt_test.dart' as jwt;

void main() {
  group('jwt', jwt.main);
  group('jwa', jwa.main);
}
