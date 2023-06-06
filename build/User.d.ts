import { IUser } from '@lumieducation/h5p-server';
/**
 * Example user object
 */
export default class User implements IUser {
    constructor();
    canCreateRestricted: boolean;
    canInstallRecommended: boolean;
    canUpdateAndInstallLibraries: boolean;
    email: string;
    id: string;
    name: string;
    type: 'local';
}
