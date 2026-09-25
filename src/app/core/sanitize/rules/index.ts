import { Rule } from '../types';
import { jwt } from './jwt/rule';

export const RULES: readonly Rule[] = [jwt];
