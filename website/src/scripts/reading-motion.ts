/** Progressive enhancement: the document is fully visible without this script. */
let cleanup = () => {};

export function initializeReadingMotion(): void {
	cleanup();
	const preference = window.matchMedia('(prefers-reduced-motion: reduce)');
	if (preference.matches || !('IntersectionObserver' in window)) return;

	const candidates = document.querySelectorAll<HTMLElement>([
		'.aq-desk > *', '.aq-packet', '.aq-roundtrip-context',
		'.sl-markdown-content > :is(.sl-heading-wrapper, h2, h3, h4, .expressive-code, .starlight-aside, table, ul, ol, .aq-actions)',
	].join(', '));
	const active = new Set<HTMLElement>();
	// Deep links and browser-restored reading positions should arrive without choreography.
	if (window.location.hash || window.scrollY > 0) return;
	const headerBottom = document.querySelector('.page > header')?.getBoundingClientRect().bottom ?? 0;

	const finish = (element: HTMLElement) => {
		element.classList.remove('aq-depth-enter', 'aq-scroll-enter');
		element.style.removeProperty('--aq-reveal-delay');
		active.delete(element);
	};
	const enter = (element: HTMLElement, opening = false) => {
		element.dataset.aqMotion = 'done';
		if (element.contains(document.activeElement) || element.querySelector(':target')) return;
		const parent = element.parentElement;
		const depth = opening && parent?.classList.contains('aq-desk');
		if (depth && parent) {
			const index = Array.from(parent.children).indexOf(element);
			element.style.setProperty('--aq-reveal-delay', `${Math.min(index * 70, 140)}ms`);
		}
		element.classList.add(depth ? 'aq-depth-enter' : 'aq-scroll-enter');
		active.add(element);
	};
	const observer = new IntersectionObserver((entries) => {
		for (const entry of entries) {
			if (!entry.isIntersecting || entry.intersectionRect.height <= 0) continue;
			const element = entry.target as HTMLElement;
			observer.unobserve(element);
			if (element.dataset.aqMotion === 'done') continue;
			enter(element);
		}
	}, { rootMargin: '0px 0px -24px 0px', threshold: 0 });

	for (const element of candidates) {
		if (element.dataset.aqMotion === 'done') continue;
		const rect = element.getBoundingClientRect();
		if (rect.bottom <= headerBottom) {
			element.dataset.aqMotion = 'done';
		} else if (rect.top < window.innerHeight - 24 && rect.bottom > headerBottom) {
			if (!element.closest('.aq-landing')) element.dataset.aqMotion = 'done';
			else enter(element, true);
		} else {
			element.dataset.aqMotion = 'pending';
			observer.observe(element);
		}
	}

	const onEnd = (event: AnimationEvent) => {
		if (event.animationName === 'aq-depth-arrive' || event.animationName === 'aq-reading-enter') {
			finish(event.target as HTMLElement);
		}
	};
	const onFocus = (event: FocusEvent) => {
		if (!(event.target instanceof Node)) return;
		for (const element of candidates) {
			if (!element.contains(event.target)) continue;
			observer.unobserve(element);
			element.dataset.aqMotion = 'done';
			finish(element);
		}
	};
	const onHash = () => {
		for (const element of active) finish(element);
		for (const element of candidates) {
			observer.unobserve(element);
			element.dataset.aqMotion = 'done';
		}
	};
	const stop = () => {
		observer.disconnect();
		for (const element of active) finish(element);
	};
	document.addEventListener('animationend', onEnd);
	document.addEventListener('focusin', onFocus);
	window.addEventListener('hashchange', onHash);
	window.addEventListener('beforeprint', stop);
	preference.addEventListener('change', initializeReadingMotion);
	cleanup = () => {
		stop();
		document.removeEventListener('animationend', onEnd);
		document.removeEventListener('focusin', onFocus);
		window.removeEventListener('hashchange', onHash);
		window.removeEventListener('beforeprint', stop);
		preference.removeEventListener('change', initializeReadingMotion);
	};
}
