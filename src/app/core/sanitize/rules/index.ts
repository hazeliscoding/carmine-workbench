import { Rule } from '../types';
import { authorizationHeaders } from './authorization-headers/rule';
import { cookies } from './cookies/rule';
import { jwt } from './jwt/rule';
import { urlParams } from './url-params/rule';

export const RULES: readonly Rule[] = [jwt, authorizationHeaders, cookies, urlParams];
