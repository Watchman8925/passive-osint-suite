import NProgress from 'nprogress';
import 'nprogress/nprogress.css';

// Configure NProgress for cyberpunk theme
NProgress.configure({
  showSpinner: false,
  speed: 200,
  minimum: 0.08,
  trickleSpeed: 200
});

export const startProgress = () => NProgress.start();
export const finishProgress = () => NProgress.done();
export const incrementProgress = () => NProgress.inc();

export default NProgress;
