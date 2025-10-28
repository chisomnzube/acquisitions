import logger from '#config/logger.js';
import { formatValidationError } from '#utils/format.js';
import { signupSchema, signinSchema } from '#validations/auth.validation.js';
import {createUser, authenticateUser} from '#services/auth.service.js';
import {jwttoken} from '#utils/jwt.js';
import {cookies} from '#utils/cookies.js';

export const signup = async (req, res, next) => {
  try {
    const validationResult = signupSchema.safeParse(req.body);
    if (!validationResult.success) {
      return res.status(400).json({
        error: 'validation failed',
        details: formatValidationError(validationResult.error)
      });
    }

    const {email, name, password, role} = validationResult.data;

    //auth service
    const user  = await createUser({name, email, password, role});

    const token  = jwttoken.sign({id: user.id, email: user.email, role: user.role});

    cookies.set(res, 'token', token);

    logger.info('User registered successfully!');
    res.status(201).json({
      message: 'User registered',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    logger.error('sign up error', error);
    if (error.message === 'User with this email already exists') {
      return res.status(409).json({ error: 'Email already exist' });
    }
    next(error);
  }
};

export const signin = async (req, res, next) => {
  try {
    const validationResult = signinSchema.safeParse(req.body);
    if (!validationResult.success) {
      return res.status(400).json({
        error: 'validation failed',
        details: formatValidationError(validationResult.error)
      });
    }

    const {email, password} = validationResult.data;

    //auth service
    const user = await authenticateUser({email, password});

    const token = jwttoken.sign({id: user.id, email: user.email, role: user.role});

    cookies.set(res, 'token', token);

    logger.info('User signed in successfully!');
    res.status(200).json({
      message: 'User signed in',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    logger.error('sign in error', error);
    if (error.message === 'User not found' || error.message === 'Invalid password') {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    next(error);
  }
};

export const signout = async (req, res, next) => {
  try {
    cookies.clear(res, 'token');

    logger.info('User signed out successfully!');
    res.status(200).json({
      message: 'User signed out successfully'
    });
  } catch (error) {
    logger.error('sign out error', error);
    next(error);
  }
};
