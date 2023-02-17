import {makeProject} from '@motion-canvas/core/lib';

import intro from './scenes/intro?scene';
import overview1 from './scenes/overview1?scene';
import exploit1 from './scenes/exploit1?scene';
import overview2 from './scenes/overview2?scene';
import exploit2 from './scenes/exploit2?scene';

export default makeProject({
  scenes: [intro, overview1, exploit1, overview2, exploit2],
  background: '#141414',
});
