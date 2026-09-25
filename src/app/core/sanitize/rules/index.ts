import { Rule } from '../types';
import { authorizationHeaders } from './authorization-headers/rule';
import { jwt } from './jwt/rule';

export const RULES: readonly Rule[] = [jwt, authorizationHeaders];
