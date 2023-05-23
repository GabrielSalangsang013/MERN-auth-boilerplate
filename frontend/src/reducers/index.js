import authenticatedReducer from './isAuthenticated';
import {combineReducers} from 'redux';

const allReducers = combineReducers({
    isAuthenticated: authenticatedReducer
});

export default allReducers;