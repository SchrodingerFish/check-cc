// CheckCC 的站点页脚组件，用于展示项目说明、官网链接、GitHub 入口和底部提示信息。
import { messages, type LocaleCode } from "@/i18n/messages";

const pageMax = "mx-auto w-full max-w-[1440px] px-5 md:px-8 2xl:max-w-[1536px] min-[1800px]:max-w-[1760px] min-[1920px]:max-w-[1920px] min-[2400px]:max-w-[2200px]";

export function SiteFooter({ locale = "zh" }: { locale?: LocaleCode }) {
  const copy = messages[locale].footer;
  return (
    <footer className="mt-20 border-t border-stone-200 bg-[#fffaf3]">
      <div className={`${pageMax} grid gap-8 py-10 lg:grid-cols-[1.15fr_0.85fr]`}>
        <section>
          <div className="text-2xl font-black text-[#0b1220]">{copy.title}</div>
          <p className="mt-4 max-w-4xl leading-8 text-stone-600">{copy.desc}</p>
        </section>
        <section className="text-sm leading-7 text-stone-600 lg:text-right">
          <div className="font-black text-[#0b1220]">{copy.infoTitle}</div>
          <p className="mt-2">{copy.feature}</p>
          <p>{copy.note}</p>
        </section>
      </div>
    </footer>
  );
}
