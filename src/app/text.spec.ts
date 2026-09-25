import { diffLines, segments } from './text';

describe('diffLines', () => {
  it('keeps shared lines and puts removals before additions', () => {
    expect(diffLines('a\nb\nc', 'a\nB\nc\nd').map((l) => `${l.op} ${l.text}`)).toEqual([
      'same a',
      'del b',
      'add B',
      'same c',
      'add d',
    ]);
  });

  it('numbers lines on each side', () => {
    const [same, del, add] = diffLines('x\ny', 'x\nz');
    expect([same.a, same.b, del.a, del.b, add.a, add.b]).toEqual([1, 1, 2, undefined, undefined, 2]);
  });
});

describe('segments', () => {
  it('marks each needle occurrence', () => {
    expect(segments("-b 'sid=<cookie:sid#3>; x'", ['<cookie:sid#3>'])).toEqual([
      { text: "-b 'sid=", hit: false },
      { text: '<cookie:sid#3>', hit: true },
      { text: "; x'", hit: false },
    ]);
  });

  it('treats needles as literal text', () => {
    expect(segments('a.b a+b', ['a+b'])).toEqual([
      { text: 'a.b ', hit: false },
      { text: 'a+b', hit: true },
    ]);
  });
});
